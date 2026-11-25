import "./isolation-guard.mjs"; // first: refuses unless no Enclaweder is reachable
import assert from "node:assert/strict";
import { test } from "node:test";
import { classifyPowerShellCommand, classifyShellCommand, splitSimpleCommand } from "../src/shell-readonly.mjs";

const READ_ONLY = [
  "ls -la",
  "ls",
  "pwd",
  "cat README.md",
  "head -n 20 src/a.ts",
  "tail -n 5 'log file.txt'",
  'grep -rn "TODO" src',
  "rg -n foo src",
  "wc -l *.ts",
  "find . -name '*.ts' -type f",
  "git status",
  "git -C sub log --oneline -5",
  "git diff HEAD~1",
  "git --no-pager show HEAD",
  "git branch -a",
  "git config --get user.name",
  "git stash list",
  "node --version",
  "date +%Y-%m-%d",
  "env",
  "sort -n numbers.txt",
  "uniq data.txt",
  "command -v node",
  "stat -c %s file",
];

const NOT_READ_ONLY = [
  ["rm -rf /", "command-not-allowlisted"],
  ["ls | sh", "shell-metacharacter"],
  ["cat a > b", "shell-metacharacter"],
  ["cat a >> b", "shell-metacharacter"],
  ["ls; rm x", "shell-metacharacter"],
  ["ls && rm x", "shell-metacharacter"],
  ["ls || rm x", "shell-metacharacter"],
  ["echo $(rm x)", "shell-metacharacter"],
  ["echo `rm x`", "shell-metacharacter"],
  ['echo "$(rm x)"', "shell-expansion"],
  ["echo $HOME", "shell-metacharacter"],
  ["cat < /etc/passwd", "shell-metacharacter"],
  ["(rm x)", "shell-metacharacter"],
  ["ls & rm x", "shell-metacharacter"],
  ["ls\nrm x", "shell-metacharacter"],
  ["cat a\\ b", "shell-metacharacter"],
  ["FOO=1 ls", "env-assignment"],
  ["find . -delete", "argument-not-read-only"],
  ["find . -exec rm {} ;", "shell-metacharacter"],
  ["find . -exec rm x", "argument-not-read-only"],
  ["sort -o out.txt in.txt", "argument-not-read-only"],
  ["uniq in out", "argument-not-read-only"],
  ["git push", "argument-not-read-only"],
  ["git commit -m x", "argument-not-read-only"],
  ["git -c core.pager=sh log", "argument-not-read-only"],
  ["git log --output=x", "argument-not-read-only"],
  ["git branch -D main", "argument-not-read-only"],
  ["git config user.name x", "argument-not-read-only"],
  ["env rm x", "argument-not-read-only"],
  ["date -s 2020-01-01", "argument-not-read-only"],
  ["hostname evil", "argument-not-read-only"],
  ["rg --pre sh foo", "argument-not-read-only"],
  ["node script.js", "argument-not-read-only"],
  ["./ls", "command-not-allowlisted"],
  ["/bin/rm -rf x", "command-not-allowlisted"],
  ["sed -i s/a/b/ f", "command-not-allowlisted"],
  ["awk 'BEGIN{system(\"rm x\")}'", "command-not-allowlisted"],
  ["curl https://example.com", "command-not-allowlisted"],
  ["'unterminated", "unbalanced-quote"],
  ["", "no-command"],
  ["ls !x", "shell-metacharacter"],
  ["ls # comment", "shell-metacharacter"],
  ["echo {a,b}", "shell-metacharacter"],
];

test("read-only commands are recognized", () => {
  for (const cmd of READ_ONLY) {
    const v = classifyShellCommand(cmd);
    assert.equal(v.readOnly, true, `${cmd}: ${JSON.stringify(v)}`);
  }
});

test("anything else is not read-only, with a reason code", () => {
  for (const [cmd, code] of NOT_READ_ONLY) {
    const v = classifyShellCommand(cmd);
    assert.equal(v.readOnly, false, cmd);
    assert.equal(v.code, code, `${cmd}: ${JSON.stringify(v)}`);
  }
});

test("non-string commands are refused", () => {
  assert.equal(classifyShellCommand(undefined).readOnly, false);
  assert.equal(classifyShellCommand({ cmd: "ls" }).readOnly, false);
});

test("quoting keeps metacharacters literal only inside single quotes", () => {
  assert.deepEqual(splitSimpleCommand("grep 'a|b;c' f"), { ok: true, argv: ["grep", "a|b;c", "f"] });
  assert.equal(splitSimpleCommand('grep "a`b" f').ok, false);
});

test("PowerShell read-only set", () => {
  assert.equal(classifyPowerShellCommand("Get-ChildItem -Recurse").readOnly, true);
  assert.equal(classifyPowerShellCommand("Get-Content a.txt").readOnly, true);
  assert.equal(classifyPowerShellCommand("Remove-Item a.txt").readOnly, false);
  assert.equal(classifyPowerShellCommand("Get-Content a | Out-File b").readOnly, false);
  assert.equal(classifyPowerShellCommand("gc $env:SECRET").readOnly, false);
});
