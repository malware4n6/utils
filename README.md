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
python3 rh2yara.py -i some.exe -o some.yara
```