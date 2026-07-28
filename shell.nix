let
  pkgs = import <nixpkgs> {};
in
  pkgs.mkShell {
    name = "suri-shell";

    buildInputs = with pkgs; [
      bash
      cargo
      rustc
      rust-cbindgen
      rust-analyzer
      tree-sitter-grammars.tree-sitter-rust
      clang
      libclang.python
      libllvm
      automake
      autoconf
      autogen
      libtool
      pkg-config
      elfutils
      jansson
      libbpf_0
      libcap_ng
      libevent
      libmaxminddb
      libnet
      libnetfilter_log
      libnetfilter_queue
      libnfnetlink
      libpcap
      libyaml
      lz4
      pcre2
      vectorscan
      zlib
      sphinx
      numactl
      dpdk
    ];

    # the following is needed to be able to build ebpf files
    hardeningDisable = [
      "zerocallusedregs"
    ];

    packages = [
      (pkgs.python3.withPackages (python-pkgs: [
        python-pkgs.pyyaml
        python-pkgs.requests
      ]))
    ];

    #shellHook = ''
    #    cargo install cbindgen
    #'';
  }
