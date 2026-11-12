"""TinyGo's JavaScript runtime, taken from the TinyGo toolchain in use."""

def _tinygo_wasm_exec_impl(ctx):
    toolchain = ctx.toolchains["@rules_tinygo//tinygo:toolchain_type"]
    matches = [f for f in toolchain.targets if f.path.endswith("/targets/wasm_exec.js")]
    if len(matches) != 1:
        fail("expected one targets/wasm_exec.js in the TinyGo toolchain, found %d" % len(matches))
    out = ctx.actions.declare_file(ctx.label.name + ".js")
    ctx.actions.symlink(output = out, target_file = matches[0])
    return [DefaultInfo(files = depset([out]))]

tinygo_wasm_exec = rule(
    implementation = _tinygo_wasm_exec_impl,
    doc = "The wasm_exec.js that matches the TinyGo toolchain, which a module it builds needs in order to run.",
    toolchains = ["@rules_tinygo//tinygo:toolchain_type"],
)
