return {
  rust_analyzer = {
    settings = {
      ['rust-analyzer'] = {
        cargo = {
          features = { 'vendored' },
        },
      },
    },
  },
}
