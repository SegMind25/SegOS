# Phase 3 conformance test: a POSIX shell script run by BusyBox's sh.
# `cargo xtask test` runs it with the same BusyBox on Linux and on SegOS;
# both must print exactly shell.expected. No pids or times in the output.
set -e
dir=/tmp/shell-test.$$
mkdir -p "$dir"
cd "$dir"

echo "# the Phase 3 demo: ls | grep | wc"
mkdir fruit
touch fruit/apple fruit/banana fruit/cherry fruit/grape
ls fruit | grep an | wc -l
ls fruit | grep -v e | wc -l
ls fruit | sort -r | head -n 2

echo "# pipelines and filters"
printf 'b\na\nc\na\n' | sort | uniq -c | sed 's/^ *//'
echo "hello world" | tr a-z A-Z | cut -d' ' -f2
seq 1 10 | awk '{ s += $1 } END { print "sum", s }'
yes | head -n 3 | wc -l

echo "# redirection"
echo hello > out.txt
echo world >> out.txt
cat < out.txt
wc -c < out.txt
ls nothing-here 2> err.txt || echo "ls failed with $?"
[ -s err.txt ] && echo "stderr went to err.txt"
exec 3> fd3.txt
echo "via fd 3" >&3
exec 3>&-
cat fd3.txt

echo "# exit status, && and ||"
set +e
false || echo "false failed"
true && echo "true succeeded"
sh -c 'exit 3'
echo "status $?"
sh -c 'kill -TERM $$'
echo "killed: status $?"
set -e

echo "# substitution, arithmetic, loops, functions"
x=$(echo sub | tr a-z A-Z)
echo "$x"
( cd fruit && ls | wc -l )
n=0
for i in 1 2 3 4 5; do n=$((n + i)); done
echo "sum $n"
square() { echo $(($1 * $1)); }
echo "square $(square 12)"
case "banana" in b*) echo "starts with b" ;; esac

echo "# background jobs and wait"
sleep 0.1 &
wait $!
echo "waited: status $?"
( sleep 0.05; exit 4 ) &
set +e
wait $!
echo "background exit $?"
set -e

echo "# traps and signals"
trap 'echo trapped USR1' USR1
kill -USR1 $$
trap - USR1
trap 'echo exit trap' EXIT
sh -c 'trap "echo child got TERM; exit 0" TERM; kill -TERM $$; sleep 1'

echo "# files, links, permissions"
ln -s fruit/apple link
readlink link
[ -L link ] && echo "is a symlink"
ln out.txt hard.txt
stat -c '%h links' out.txt
mv out.txt moved.txt
head -n 1 moved.txt
chmod 640 moved.txt
stat -c %a moved.txt
mkdir -p a/b/c && touch a/b/c/deep
find a -type f
rm -r a
[ -d a ] || echo "a removed"
echo "abc" > f && cp f g && cmp f g && echo "copies match"

echo "# here-document and read"
cat <<END
line one
line two
END
printf 'first second\n' | { read a b; echo "$b $a"; }

echo "# /proc"
[ "$(readlink /proc/self)" -gt 0 ] && echo "/proc/self is a pid"
grep -c '^MemTotal:' /proc/meminfo
cat /proc/self/comm

cd /
rm -rf "$dir"
echo done
