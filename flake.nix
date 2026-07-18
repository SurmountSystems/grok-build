{
  description = "Grok OSS - unofficial open-source fork of xAI Grok Build";

  # Input surface is intentionally small (no flake-utils / systems).
  # github: still uses the tarball API, but with fewer inputs and NIX_CONFIG
  # download-attempts + just nix_retry we survive free-GHA 502/503s.
  # Avoid git+https for nixpkgs: a full clone is multi-GB and more fragile
  # on free runners than a single tarball of the locked rev.
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

    fenix = {
      url = "github:nix-community/fenix";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    crane.url = "github:ipetkov/crane";
  };

  outputs =
    {
      self,
      nixpkgs,
      fenix,
      crane,
    }:
    let
      # Same default set flake-utils used; no extra flake input to fetch.
      systems = [
        "x86_64-linux"
        "aarch64-linux"
        "x86_64-darwin"
        "aarch64-darwin"
      ];
      forAllSystems = nixpkgs.lib.genAttrs systems;

      perSystem = forAllSystems (
        system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
          inherit (pkgs) lib;

          # Match rust-toolchain.toml (channel 1.92.0 + clippy/rustfmt).
          rustToolchain = fenix.packages.${system}.fromToolchainFile {
            file = ./rust-toolchain.toml;
            sha256 = "sha256-sqSWJDUxc+zaz1nBWMAJKTAGBuGWP25GCftIOlCEAtA=";
          };

          craneLib = (crane.mkLib pkgs).overrideToolchain rustToolchain;

          # ------------------------------------------------------------------
          # cargo-mem-guard
          #
          # Standalone crate under crates/codegen/ (workspace-excluded). Built
          # with a fileset root so crane never sees the monorepo Cargo.toml.
          # On Linux the binary is wrapped with mold on PATH and mold-friendly
          # defaults -- pure Nix, no host PATH / bash scripts.
          # ------------------------------------------------------------------
          memGuardRoot = ./crates/codegen/cargo-mem-guard;

          memGuardSrc = lib.fileset.toSource {
            root = memGuardRoot;
            fileset = lib.fileset.unions [
              (memGuardRoot + /Cargo.toml)
              (memGuardRoot + /Cargo.lock)
              (memGuardRoot + /src)
            ];
          };

          memGuardCrate = craneLib.crateNameFromCargoToml {
            cargoToml = memGuardRoot + /Cargo.toml;
          };

          memGuardCommonArgs = {
            inherit (memGuardCrate) pname version;
            src = memGuardSrc;
            strictDeps = true;
            # Pure std; no openssl / dbus / protoc.
            meta = {
              description = "Memory-aware cargo wrapper for constrained CI runners";
              homepage = "https://github.com/SurmountSystems/grok-oss";
              license = lib.licenses.asl20;
              mainProgram = "cargo-mem-guard";
              platforms = lib.platforms.unix;
            };
          };

          # Install package only (no unit tests here). Tests live solely in
          # checks.cargo-mem-guard-tests so free GHA / mem-guard does not pay
          # for the suite twice (package doCheck + separate check attr).
          cargo-mem-guard-unwrapped = craneLib.buildPackage (
            memGuardCommonArgs
            // {
              doCheck = false;
            }
          );

          # Unit tests as the single flake check for this crate.
          cargo-mem-guard-tests = craneLib.cargoTest (
            memGuardCommonArgs
            // {
              cargoArtifacts = craneLib.buildDepsOnly memGuardCommonArgs;
            }
          );

          # Bake mold into the runtime closure on Linux so CARGO_MEM_USE_MOLD
          # works without relying on the ambient host PATH.
          cargo-mem-guard =
            if pkgs.stdenv.isLinux then
              pkgs.symlinkJoin {
                name = "${memGuardCrate.pname}-${memGuardCrate.version}";
                paths = [ cargo-mem-guard-unwrapped ];
                nativeBuildInputs = [ pkgs.makeWrapper ];
                postBuild = ''
                  wrapProgram $out/bin/cargo-mem-guard \
                    --prefix PATH : ${lib.makeBinPath [ pkgs.mold ]} \
                    --set-default CARGO_MEM_USE_MOLD 1
                '';
                meta = cargo-mem-guard-unwrapped.meta // {
                  description = "${cargo-mem-guard-unwrapped.meta.description} (with mold)";
                };
              }
            else
              cargo-mem-guard-unwrapped;

          # ------------------------------------------------------------------
          # grok-oss monorepo (crane)
          # ------------------------------------------------------------------
          src = lib.cleanSourceWith {
            src = ./.;
            filter =
              path: type:
              let
                base = baseNameOf path;
              in
              (craneLib.filterCargoSources path type)
              || lib.hasInfix "/crates/" path
              || lib.hasInfix "/prod/" path
              || lib.hasInfix "/third_party/" path
              || lib.hasInfix "/bin/" path
              || base == "rust-toolchain.toml"
              || base == "clippy.toml"
              || base == "rustfmt.toml"
              || base == "protoc";
          };

          nativeBuildInputs =
            with pkgs;
            [
              pkg-config
              protobuf
              cmake
              perl
              ripgrep
              makeWrapper
            ]
            ++ lib.optionals stdenv.isLinux [
              # Faster, leaner final links on Linux (helps free GHA RAM peaks).
              mold
            ];

          buildInputs =
            with pkgs;
            [ openssl ]
            ++ lib.optionals stdenv.isLinux [ dbus ]
            ++ lib.optionals stdenv.isDarwin [
              darwin.apple_sdk.frameworks.Security
              darwin.apple_sdk.frameworks.SystemConfiguration
            ];

          # Linux: prefer mold for links inside pure crane builds.
          moldRustflags = lib.optionalString pkgs.stdenv.isLinux "-C link-arg=-fuse-ld=mold";

          commonArgs = {
            inherit src nativeBuildInputs buildInputs;
            strictDeps = true;
            pname = "grok-oss";
            version =
              (craneLib.crateNameFromCargoToml {
                cargoToml = ./crates/codegen/xai-grok-pager-bin/Cargo.toml;
              }).version;
            PROTOC = "${pkgs.protobuf}/bin/protoc";
            OPENSSL_NO_VENDOR = "1";
            GROK_TOOLS_BUNDLE_RG_PATH = "${pkgs.ripgrep}/bin/rg";
            GROK_SHELL_BUNDLE_RG_PATH = "${pkgs.ripgrep}/bin/rg";
            GROK_GIT_SHA = self.shortRev or self.dirtyShortRev or "unknown";
            # Cap cargo fan-out inside the pure sandbox (free GHA ~16GB).
            CARGO_BUILD_JOBS = "2";
            RUSTFLAGS = moldRustflags;
          };

          cargoArtifacts = craneLib.buildDepsOnly (
            commonArgs
            // {
              cargoExtraArgs = "-p xai-grok-pager-bin";
            }
          );

          grok-oss = craneLib.buildPackage (
            commonArgs
            // {
              inherit cargoArtifacts;
              cargoExtraArgs = "-p xai-grok-pager-bin";
              postInstall = ''
                wrapProgram $out/bin/grok-oss \
                  --prefix LD_LIBRARY_PATH : ${lib.makeLibraryPath buildInputs}
              '';
              meta = {
                description = "Unofficial open-source Grok Build coding agent (Surmount fork)";
                homepage = "https://github.com/SurmountSystems/grok-oss";
                license = lib.licenses.asl20;
                mainProgram = "grok-oss";
              };
            }
          );

          cargoCheck = craneLib.mkCargoDerivation (
            commonArgs
            // {
              inherit cargoArtifacts;
              pnameSuffix = "-check";
              buildPhaseCargoCommand = "cargoWithProfile check -p xai-grok-pager-bin --locked";
            }
          );

          openrouter-credentials = craneLib.cargoTest (
            commonArgs
            // {
              inherit cargoArtifacts;
              cargoExtraArgs = "-p xai-grok-shell";
              cargoTestExtraArgs = "--test openrouter_credentials";
              preCheck = ''
                export LD_LIBRARY_PATH="${lib.makeLibraryPath buildInputs}''${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
              '';
            }
          );

          # ------------------------------------------------------------------
          # Host CI toolchain (free GHA / low-mem)
          #
          # A single buildEnv so consumers can:
          #   nix shell .#ci-tools -c cargo-mem-guard -- cargo check ...
          #   nix develop .#ci
          # without assembling PATH by hand or writing bash wrappers.
          # ------------------------------------------------------------------
          ciLowMemEnv = {
            CARGO_MEM_JOBS_START = "2";
            CARGO_MEM_JOBS_MIN = "1";
            CARGO_MEM_HIGH_WATER = "0.15";
            CARGO_MEM_MAX_RESTARTS = "3";
            CARGO_MEM_USE_MOLD = if pkgs.stdenv.isLinux then "1" else "0";
            PROTOC = "${pkgs.protobuf}/bin/protoc";
            OPENSSL_NO_VENDOR = "1";
            GROK_TOOLS_BUNDLE_RG_PATH = "${pkgs.ripgrep}/bin/rg";
            GROK_SHELL_BUNDLE_RG_PATH = "${pkgs.ripgrep}/bin/rg";
            PKG_CONFIG_PATH = lib.makeSearchPathOutput "dev" "lib/pkgconfig" (
              [ pkgs.openssl ] ++ lib.optionals pkgs.stdenv.isLinux [ pkgs.dbus ]
            );
            LD_LIBRARY_PATH = lib.makeLibraryPath (
              [ pkgs.openssl ] ++ lib.optionals pkgs.stdenv.isLinux [ pkgs.dbus ]
            );
            # mkShell injects NIX_HARDENING_ENABLE with fortify. jemalloc's
            # configure runs C probes under -O0 -Werror; fortify then emits
            # "_FORTIFY_SOURCE requires -O" and the probe fails as
            # "cannot determine return type of strerror_r". Host cargo CI
            # is not a pure nix build -- disable fortify for configure probes.
            NIX_HARDENING_ENABLE = "bindnow format pic relro stackprotector strictoverflow";
          };

          # Tiny bootstrap package: locked nixpkgs `just` only (no rustc).
          # GHA cold-start uses `nix shell .#just -c just ci` so free runners
          # never hit unpinned `nix shell nixpkgs#just` registry tarballs.
          # Note: evaluating .#just still loads full flake inputs (nixpkgs /
          # fenix / crane) once; only the realized closure is just-only.
          justPkg = pkgs.just;

          ci-tools = pkgs.buildEnv {
            name = "grok-oss-ci-tools";
            paths =
              [
                rustToolchain
                cargo-mem-guard
                pkgs.pkg-config
                pkgs.protobuf
                pkgs.cmake
                pkgs.openssl
                pkgs.perl
                pkgs.ripgrep
                justPkg
              ]
              ++ lib.optionals pkgs.stdenv.isLinux [
                pkgs.mold
                pkgs.dbus
              ];
            pathsToLink = [
              "/bin"
              "/lib"
              "/include"
              "/lib/pkgconfig"
              "/share"
            ];
            meta = {
              description = "Host CI toolchain: fenix rustc, cargo-mem-guard, mold, build deps";
              homepage = "https://github.com/SurmountSystems/grok-oss";
              license = lib.licenses.asl20;
            };
          };

          devShell = pkgs.mkShell {
            packages = [
              rustToolchain
              pkgs.rust-analyzer
              pkgs.pkg-config
              pkgs.protobuf
              pkgs.cmake
              pkgs.openssl
              pkgs.git
              pkgs.ripgrep
              cargo-mem-guard
            ]
            ++ lib.optionals pkgs.stdenv.isLinux [
              pkgs.dbus
              pkgs.mold
            ];

            # Share host-cargo env with .#ci so jemalloc configure works here too
            # (fortify-off via NIX_HARDENING_ENABLE; see ciLowMemEnv comment).
            inherit (ciLowMemEnv)
              PROTOC
              OPENSSL_NO_VENDOR
              GROK_TOOLS_BUNDLE_RG_PATH
              GROK_SHELL_BUNDLE_RG_PATH
              NIX_HARDENING_ENABLE
              ;

            shellHook = ''
              echo "Grok OSS dev shell (fenix from rust-toolchain.toml)"
              echo "  cargo build -p xai-grok-pager-bin --release"
              echo "  nix run .#cargo-mem-guard -- cargo check -p xai-grok-pager-bin --locked"
              echo "  nix build .#grok-oss"
              echo "  nix build .#cargo-mem-guard"
              echo "  nix shell .#ci-tools"
            '';
          };

          # Free-GHA / low-mem host builds: same tools as packages.ci-tools,
          # plus the pressure-restart defaults as shell env.
          ciShell = pkgs.mkShell {
            packages = [ ci-tools ];
            env = ciLowMemEnv;
          };

        in
        {
          inherit
            grok-oss
            cargo-mem-guard
            cargo-mem-guard-unwrapped
            cargo-mem-guard-tests
            cargoCheck
            openrouter-credentials
            justPkg
            ci-tools
            devShell
            ciShell
            ;
        }
      );
    in
    {
      packages = forAllSystems (
        system:
        let
          p = perSystem.${system};
        in
        {
          default = p.grok-oss;
          # Alias: `nix shell .#just` -> locked nixpkgs just (bootstrap only).
          just = p.justPkg;
          inherit (p)
            grok-oss
            cargo-mem-guard
            ci-tools
            cargo-mem-guard-unwrapped
            ;
        }
      );

      checks = forAllSystems (
        system:
        let
          p = perSystem.${system};
        in
        {
          inherit (p)
            grok-oss
            cargoCheck
            openrouter-credentials
            cargo-mem-guard
            cargo-mem-guard-tests
            ;
        }
      );

      apps = forAllSystems (
        system:
        let
          p = perSystem.${system};
        in
        {
          default = {
            type = "app";
            program = "${p.grok-oss}/bin/grok-oss";
          };
          cargo-mem-guard = {
            type = "app";
            program = "${p.cargo-mem-guard}/bin/cargo-mem-guard";
          };
        }
      );

      devShells = forAllSystems (
        system:
        let
          p = perSystem.${system};
        in
        {
          default = p.devShell;
          ci = p.ciShell;
        }
      );
    };
}
