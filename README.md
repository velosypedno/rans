# Навчальний Mock Ransomware 

Навчальний проект для демонстрації принципів роботи гібридного шифрування у межах дисципліни «Комп'ютерна вірусологія».

---

## Архітектура та принцип роботи

1. **Гібридне шифрування:**
   * Кожен файл у цільовій директорії шифрується окремим випадковим симетричним ключем (AES).
   * Структура та назви файлів залишаються незмінними, але їхній вміст повністю перезаписується у зашифрованому вигляді.
   * Програма створює словник відповідності `map[string]string` у форматі `{"шлях_до_файлу": "aes_ключ"}`.

2. **Захист метаданих (RSA):**
   * Словник серіалізується в JSON-байти.
   * Ці байти шифруються асиметричним публічним ключем RSA (`sshPubKey`), зашитим у код шифрувальника.
   * Результат разом із зашифрованими даними зберігається у службовий файл `lock.dat`.

3. **Дешифрування:**
   * Програма-дешифрувач використовує вбудований приватний ключ (`privPEM`), розшифровує таблицю ключів із `lock.dat`, а потім відновлює кожен файл за його унікальним AES-ключем.

---

## Швидкий старт

### 1. Генерація ключів
Для роботи потрібна пара RSA-ключів, створена через OpenSSH:
```bash
ssh-keygen -t rsa -b 2048 -m PEM -f ./ransom_key -N ""
```
У результаті з'являться файли ransom_key (приватний) та ransom_key.pub (публічний). Їхні значення вставляються константами у відповідні бінарники (encrypt та decrypt).


### 2. Запуск шифрування
Запуск шифрування. Опціонально вказується шлях до папки (за замовчуванням — поточна). Під час виконання програма зашифрує файли, створить службовий файл lock.dat з метаданними та текстовий файл з вимогами README_FOR_DECRYPT.txt:
```bash
go run cmd/encrypt/main.go [шлях_до_директорії]
```

### 3. Запуск дешифрування
Відновлення файлів за допомогою зашифрованого файлу lock.dat та приватного ключа:
```bash
go run cmd/decrypt/main.go [шлях_до_директорії]
```


## Трошки довший сетап

### 1. Клмпіляція банарників
```bash
go build -o ./encrypt ./cmd/encrypt/main.go
go build -o ./decrypt ./cmd/decrypt/main.go
```

### Приклади використання

```bash
➜  ransomware git:(main) ✗ ./encrypt ./example 
[*] Target directory: ./example
[Encrypted] example/README.md
[Encrypted] example/pacman_pkgs.txt
[Encrypted] example/we.jpg
[Encrypted] example/Варіанти_завдань_3.pdf
[+] Encryption complete. lock.dat and ransom note created.
➜  ransomware git:(main) ✗ ./decrypt ./example
[*] Target directory for decryption: ./example
[Decrypted] example/we.jpg
[Decrypted] example/Варіанти_завдань_3.pdf
[Decrypted] example/README.md
[Decrypted] example/pacman_pkgs.txt
[+] Decryption complete. All files successfully restored.
➜  ransomware git:(main) ✗ 
```
