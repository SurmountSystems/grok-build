{
  description = "Grok OSS — unofficial open-source fork of xAI Grok Build";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

    fenix = {
      url = "github:nix-community/fenix";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    crane.url = "github:ipetkov/crane";

    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs =
    {
      self,
      nixpkgs,
      fenix,
      crane,
      flake-utils,
    }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = nixpkgs.legacyPackages.${system};

        # Match rust-toolchain.toml (channel 1.92.0 + clippy/rustfmt).
        rustToolchain = fenix.packages.${system}.fromToolchainFile {
          file = ./rust-toolchain.toml;
          sha256 = "sha256-sqSWJDUxc+zaz1nBWMAJKTAGBuGWP25GCftIOlCEAtA=";
        };

        craneLib = (crane.mkLib pkgs).overrideToolchain rustToolchain;

        src = pkgs.lib.cleanSourceWith {
          src = ./.;
          filter =
            path: type:
            let
              base = baseNameOf path;
            in
            (craneLib.filterCargoSources path type)
            || pkgs.lib.hasInfix "/crates/" path
            || pkgs.lib.hasInfix "/prod/" path
            || pkgs.lib.hasInfix "/third_party/" path
            || pkgs.lib.hasInfix "/bin/" path
            || base == "rust-toolchain.toml"
            || base == "clippy.toml"
            || base == "rustfmt.toml"
            || base == "protoc";
        };

        nativeBuildInputs = with pkgs; [
          pkg-config
          protobuf
          cmake
          perl
          ripgrep # offline bundle for xai-grok-tools / shell build.rs
          makeWrapper
        ];

        buildInputs =
          with pkgs;
          [ openssl ]
          ++ lib.optionals stdenv.isLinux [ dbus ]
          ++ lib.optionals stdenv.isDarwin [
            darwin.apple_sdk.frameworks.Security
            darwin.apple_sdk.frameworks.SystemConfiguration
          ];

        commonArgs = {
          inherit src nativeBuildInputs buildInputs;
          strictDeps = true;
          pname = "grok-oss";
          version =
            (craneLib.crateNameFromCargoToml {
              cargoToml = ./crates/codegen/xai-grok-pager-bin/Cargo.toml;
            }).version;
          # Prefer nix protoc over the repo's dotslash launcher.
          PROTOC = "${pkgs.protobuf}/bin/protoc";
          OPENSSL_NO_VENDOR = "1";
          # build.rs scripts download musl rg unless these are set (nix builds are pure).
          GROK_TOOLS_BUNDLE_RG_PATH = "${pkgs.ripgrep}/bin/rg";
          GROK_SHELL_BUNDLE_RG_PATH = "${pkgs.ripgrep}/bin/rg";
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
            # Runtime shared libs (dbus/openssl) must be on the rpath.
            postInstall = ''
              wrapProgram $out/bin/grok-oss \
                --prefix LD_LIBRARY_PATH : ${pkgs.lib.makeLibraryPath buildInputs}
            '';
            meta = with pkgs.lib; {
              description = "Unofficial open-source Grok Build coding agent (Surmount fork)";
              homepage = "https://github.com/SurmountSystems/grok-oss";
              license = licenses.asl20;
              mainProgram = "grok-oss";
            };
          }
        );

        # crane has no cargoCheck helper; mkCargoDerivation + `cargo check`.
        cargoCheck = craneLib.mkCargoDerivation (
          commonArgs
          // {
            inherit cargoArtifacts;
            pnameSuffix = "-check";
            buildPhaseCargoCommand = "cargoWithProfile check -p xai-grok-pager-bin --locked";
          }
        );

        # Focused integration test for the OpenRouter fork feature.
        # keyring/dbus link at runtime — pure sandbox has no host libdbus.
        openrouter-credentials = craneLib.cargoTest (
          commonArgs
          // {
            inherit cargoArtifacts;
            cargoExtraArgs = "-p xai-grok-shell";
            cargoTestExtraArgs = "--test openrouter_credentials";
            preCheck = ''
              export LD_LIBRARY_PATH="${pkgs.lib.makeLibraryPath buildInputs}''${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
            '';
          }
        );
      in
      {
        packages = {
          default = grok-oss;
          inherit grok-oss;
        };

        checks = {
          inherit grok-oss cargoCheck openrouter-credentials;
        };

        apps.default = flake-utils.lib.mkApp {
          drv = grok-oss;
        };

        devShells.default = pkgs.mkShell {
          packages = [
            rustToolchain
            pkgs.rust-analyzer
            pkgs.pkg-config
            pkgs.protobuf
            pkgs.cmake
            pkgs.openssl
            pkgs.git
            pkgs.ripgrep
          ] ++ pkgs.lib.optionals pkgs.stdenv.isLinux [ pkgs.dbus ];

          PROTOC = "${pkgs.protobuf}/bin/protoc";
          OPENSSL_NO_VENDOR = "1";
          GROK_TOOLS_BUNDLE_RG_PATH = "${pkgs.ripgrep}/bin/rg";
          GROK_SHELL_BUNDLE_RG_PATH = "${pkgs.ripgrep}/bin/rg";

          shellHook = ''
            echo "Grok OSS dev shell (fenix from rust-toolchain.toml)"
            echo "  cargo build -p xai-grok-pager-bin --release   # → target/release/grok-oss"
            echo "  cargo test  -p xai-grok-shell --test openrouter_credentials"
            echo "  nix build .#grok-oss"
          '';
        };
      }
    );
}
