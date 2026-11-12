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

_GoModulesInfo = provider(doc = "The external repositories a Go target is built from.", fields = ["repos"])

def _go_modules_aspect_impl(target, ctx):
    transitive = []
    for attr in ("deps", "embed"):
        for dep in getattr(ctx.rule.attr, attr, []):
            if _GoModulesInfo in dep:
                transitive.append(dep[_GoModulesInfo].repos)
    repo = target.label.repo_name
    return [_GoModulesInfo(repos = depset([repo] if repo else [], transitive = transitive))]

_go_modules_aspect = aspect(
    implementation = _go_modules_aspect_impl,
    attr_aspects = ["deps", "embed"],
)

def _wasm_notices_impl(ctx):
    toolchain = ctx.toolchains["@rules_tinygo//tinygo:toolchain_type"]

    # The Go modules listed must be exactly the ones linked. A module's
    # repository is named for it, after the extension that made it:
    # gazelle++go_deps+org_golang_x_mod.
    linked = sorted([r.rpartition("+")[2] for r in ctx.attr.binary[_GoModulesInfo].repos.to_list()])
    listed = sorted(ctx.attr.modules.keys())
    if linked != listed:
        fail("%s lists the licences of %s, but %s is built from %s: add or remove verifier/licenses/<module>.txt and its title" %
             (ctx.label, listed, ctx.attr.binary.label, linked))
    by_name = {f.basename: f for f in ctx.files.module_licenses}

    parts = []  # (title, file)
    for module, title in ctx.attr.modules.items():
        if module + ".txt" not in by_name:
            fail("no licence file %s.txt among module_licenses" % module)
        parts.append((title, by_name[module + ".txt"]))
    for target, title in ctx.attr.licenses.items():
        files = target.files.to_list()
        if len(files) != 1:
            fail("%s: expected one licence file, found %d" % (target.label, len(files)))
        parts.append((title, files[0]))
    for suffix, title in ctx.attr.toolchain_licenses.items():
        matches = [f for f in toolchain.libs if f.path.endswith("/" + suffix)]
        if len(matches) != 1:
            fail("expected one %s in the TinyGo toolchain, found %d" % (suffix, len(matches)))
        parts.append((title, matches[0]))

    out = ctx.actions.declare_file(ctx.attr.out)
    args = ctx.actions.args()
    args.add(out)
    args.add(ctx.attr.header.replace("{tinygo}", toolchain.version))
    for title, f in parts:
        args.add(title)
        args.add(f)
    ctx.actions.run_shell(
        outputs = [out],
        inputs = [f for _, f in parts],
        arguments = [args],
        command = """
out="$1"; header="$2"; shift 2
{
  printf '%s\\n' "$header"
  while [ $# -gt 0 ]; do
    printf '\\n%s\\n%s\\n\\n' "------------------------------------------------------------------------" "$1"
    cat "$2"
    shift 2
  done
} > "$out"
""",
        mnemonic = "WasmNotices",
    )
    return [DefaultInfo(files = depset([out]))]

wasm_notices = rule(
    implementation = _wasm_notices_impl,
    doc = """The licences of everything compiled into a TinyGo WebAssembly module, as one text file.

The build fails if the Go modules listed are not exactly those the module is built from.""",
    attrs = {
        "out": attr.string(mandatory = True),
        "header": attr.string(mandatory = True, doc = "Opening text; {tinygo} is replaced by the toolchain's version."),
        "binary": attr.label(mandatory = True, aspects = [_go_modules_aspect], doc = "The Go library compiled into the module."),
        "modules": attr.string_dict(doc = "Go module, by the name of its repository, to the title to print above its licence."),
        "module_licenses": attr.label_list(allow_files = [".txt"], doc = "<module>.txt for each of modules."),
        "licenses": attr.label_keyed_string_dict(allow_files = True, doc = "Any other licence file, to its title."),
        "toolchain_licenses": attr.string_dict(doc = "Path of a licence file under the TinyGo toolchain, to its title."),
    },
    toolchains = ["@rules_tinygo//tinygo:toolchain_type"],
)
