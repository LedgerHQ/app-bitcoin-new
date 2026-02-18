# Compatibility wrapper for nix-shell users
# This imports the devShell from flake.nix - use `nix develop` for the native flake experience
(builtins.getFlake (toString ./.)).devShells.${builtins.currentSystem}.default
