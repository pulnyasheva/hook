# hook

## Для сборки 
1. Перейти в директорию hook
2. docker build <BUILD_INLINE_TEST=ON> <BUILD_GOTPLT_TEST=ON> -t libs .
3. docker run --rm -v <путь до директории на ноутбуке>:/output libs:latest