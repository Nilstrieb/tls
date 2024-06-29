{ pkgs ? import <nixpkgs> { } }: pkgs.mkShell {
  buildInputs = with pkgs; [

  ];
  RUST_BACKTRACE = 1;
  packages = (with pkgs; [
    wireshark
  ]);
}
