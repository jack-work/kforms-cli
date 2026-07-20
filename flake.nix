{
  description = "gforms-cli — CLI for the gluck-forms API";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  };

  outputs = { self, nixpkgs }:
    let
      supportedSystems = [
        "x86_64-linux"
        "aarch64-linux"
        "aarch64-darwin"
        "x86_64-darwin"
      ];
      forAllSystems = f: nixpkgs.lib.genAttrs supportedSystems (system: f {
        pkgs = nixpkgs.legacyPackages.${system};
      });
    in
    {
      # Note: go.mod carries a local-path `replace` for
      # github.com/jack-work/hush, so a fully reproducible
      # buildGoModule is intentionally not exposed here — it would
      # need the replace target available at eval time. For local
      # dev, `go build ./...` from the devShell just works.
      devShells = forAllSystems ({ pkgs }: {
        default = pkgs.mkShell {
          packages = with pkgs; [ go gopls git ];
          shellHook = ''
            echo "gforms-cli dev shell — try: go build ./..."
          '';
        };
      });
    };
}
