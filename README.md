# Misc small tools I don't want to write again

cat some_git.txt | xargs -I {} git clone --recurse-submodules {}

## Git monitoring: `gitmon`

Considering $ROOT_FOLDER that contains some `git clone`, `gitmon` calls `git pull origin` on each git repository and only displays the projects that have updates.

```sh
gitmon.sh $ROOT_FOLDER
```

For more details, read the header of [gitmon.sh](gitmon.sh).

## Rich Header to Yara

```sh
usage: rh2yara.py [-h] [--version] -i INPUT [-o OUTPUT] [-v]

Rich Header to Yara

options:
  -h, --help            show this help message and exit
  --version             show program's version number and exit
  -i INPUT, --input INPUT
                        path to some exe (use -i for each input file)
  -o OUTPUT, --output OUTPUT
                        path to generated Yara
  -v, --verbose         set loglevel to DEBUG


python3 rh2yara.py -i some.exe -i some2.exe -o some.yara
```