{
  description = "Ledger Bitcoin App development environment";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.11";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs { inherit system; };
        clang = pkgs.llvmPackages_19.clang-unwrapped;
        clangResources = pkgs.llvmPackages_19.clang-unwrapped.lib;
        lld = pkgs.llvmPackages_19.lld;
      in
      {
        devShells.default = pkgs.mkShell {
          buildInputs = with pkgs; [
            # Build toolchain
            gnumake
            gcc-arm-embedded
            clang
            lld
            python313
            python313Packages.pillow
            python313Packages.setuptools

            # Python venv for ledgerblue / speculos
            python312
            python312Packages.pip
            python312Packages.virtualenv

            # USB/HID for device communication
            libusb1
            hidapi

            # Bitcoin Core (bitcoind + bitcoin-cli for regtest)
            bitcoind

            # General build deps
            zlib
            jq
            git
            bash

            # Speculos simulator
            qemu
            cmake
            pkg-config
            libvncserver

            # Rust for test dependencies
            rustc
            cargo

            # Build tools for coincurve/secp256k1
            autoconf
            automake
            libtool
            secp256k1

            # OpenGL/Qt support for Speculos GUI
            libGL
            xorg.libX11
            xorg.libXext
            libxkbcommon
            fontconfig
            freetype
            glib
            zstd
            dbus
            xorg.xcbutilcursor
            xorg.libxcb
            xorg.xcbutilimage
            xorg.xcbutilkeysyms
            xorg.xcbutilwm
            xorg.xcbutilrenderutil
            xorg.xcbutil
            wayland
          ];

          shellHook = ''
            # --- BOLOS SDK ---
            if [ -z "$BOLOS_SDK" ]; then
              if [ -d "../ledger-secure-sdk" ]; then
                export BOLOS_SDK="$(cd ../ledger-secure-sdk && pwd)"
              elif [ -d "$HOME/ledger-secure-sdk" ]; then
                export BOLOS_SDK="$HOME/ledger-secure-sdk"
              else
                echo "WARNING: BOLOS_SDK not set and ledger-secure-sdk not found."
                echo "  git clone https://github.com/LedgerHQ/ledger-secure-sdk ../ledger-secure-sdk"
              fi
            fi

            # --- Toolchain paths ---
            export TARGET=''${TARGET:-stax}
            export GCCPATH=${pkgs.gcc-arm-embedded}/bin/
            export CLANGPATH=${clang}/bin/

            # Clang resource dir for builtin headers (stdbool.h, etc.)
            # Uses LEDGER_CFLAGS to avoid polluting pip/venv builds
            ARM_INCLUDE="${pkgs.gcc-arm-embedded}/arm-none-eabi/include"
            export LEDGER_CFLAGS="-resource-dir=${clangResources}/lib/clang/19 -isystem $ARM_INCLUDE"

            # --- Shell fixups for NixOS ---
            mkdir -p .nix-bin
            ln -sf ${pkgs.bash}/bin/bash .nix-bin/bash
            ln -sf ${pkgs.qemu}/bin/qemu-arm .nix-bin/qemu-arm-static
            export PATH="${lld}/bin:$PWD/.nix-bin:$PATH"
            export SHELL=${pkgs.bash}/bin/bash

            # --- Library paths ---
            export LD_LIBRARY_PATH="${pkgs.stdenv.cc.cc.lib}/lib:${pkgs.zlib}/lib:${pkgs.libusb1}/lib:${pkgs.hidapi}/lib:${pkgs.secp256k1}/lib:${pkgs.libGL}/lib:${pkgs.xorg.libX11}/lib:${pkgs.xorg.libXext}/lib:${pkgs.libxkbcommon}/lib:${pkgs.fontconfig.lib}/lib:${pkgs.freetype}/lib:${pkgs.glib.out}/lib:${pkgs.zstd.out}/lib:${pkgs.dbus.lib}/lib:${pkgs.xorg.xcbutilcursor}/lib:${pkgs.xorg.libxcb}/lib:${pkgs.xorg.xcbutilimage}/lib:${pkgs.xorg.xcbutilkeysyms}/lib:${pkgs.xorg.xcbutilwm}/lib:${pkgs.xorg.xcbutilrenderutil}/lib:${pkgs.xorg.xcbutil}/lib:${pkgs.wayland}/lib:$LD_LIBRARY_PATH"
            export PKG_CONFIG_PATH="${pkgs.secp256k1}/lib/pkgconfig:$PKG_CONFIG_PATH"

            # --- Python venv (ledgerblue for device loading, speculos for simulation) ---
            if [ ! -d .venv ]; then
              echo "Creating Python venv for ledgerblue, speculos, and ragger..."
              python3.12 -m venv .venv
              .venv/bin/pip install --quiet ledgerblue ledgerwallet
              .venv/bin/pip install --quiet speculos ragger[speculos]
            fi
            source .venv/bin/activate

            if ! python -c "import ledgerblue" 2>/dev/null; then
              echo "Installing ledgerblue..."
              pip install --quiet ledgerblue ledgerwallet
            fi
          '';
        };
      });
}
