# Task 1 — Find Abnormal Logon (Forensics)
 
**Платформа:** ctf.rteam.kz  
**Категория:** Forensics  
**Файл:** `Security-filtered.evtx` (Windows Security Event Log)
 
---
 
## Инструменты
 
- Kali Linux
- [evtx_dump](https://github.com/omerbenamram/evtx) — парсер .evtx файлов (Rust)
- `grep`, `python3`
---
 
## Шаг 1 — Скачать и подготовить evtx_dump
 
```bash
wget https://github.com/omerbenamram/evtx/releases/download/v0.8.1/evtx_dump-v0.8.1-x86_64-unknown-linux-musl -O evtx_dump
chmod +x evtx_dump
```
 
## Шаг 2 — Конвертировать .evtx в JSON
 
```bash
./evtx_dump Security-filtered.evtx -o jsonl -f sec.jsonl
```
 
Результат: файл `sec.jsonl` (~22 MB, 21746 событий)
 
---
 
## Анализ
 
### Аккаунты, которые входили на хост
 
```bash
grep '"EventID":4624' sec.jsonl | grep -o '"TargetUserName":"[^"]*"' | sort | uniq -c | sort -rn
```
 
Основные пользователи:
- `tdungan` — RDP и сетевой вход
- `wacsvc` — RDP переподключения
- `rsydow-a` — административный вход (107 раз)
- `cbarton-a` — административный вход (26 раз)
### Типы входа (Logon Types)
 
| Тип | Описание |
|-----|----------|
| 3   | Network (сетевой) |
| 5   | Service (сервисный) |
| 10  | RemoteInteractive (RDP) |
 
### Неудачные попытки входа (Event ID 4625)
 
```bash
grep '"EventID":4625' sec.jsonl | grep -o '"TargetUserName":"[^"]*"' | sort | uniq -c | sort -rn
```
 
Результат:
```
14  "TargetUserName":"sprx"
```
 
Аккаунт `sprx` — **14 неудачных попыток** входа. Время попыток:
 
| Время (UTC) |
|-------------|
| 2023-01-17T14:41:59 |
| 2023-01-18T14:49:51 |
| 2023-01-18T14:50:31 |
| 2023-01-18T15:26:20 |
| 2023-01-18T15:26:51 |
| 2023-01-18T20:30:15 |
| 2023-01-18T20:31:27 |
| 2023-01-18T21:34:00 |
| 2023-01-18T21:47:56 |
| 2023-01-19T14:27:56 |
| 2023-01-19T18:45:34 |
| 2023-01-19T18:48:08 |
| 2023-01-19T20:25:23 |
| ... |
 
> Примечательно: неудачные попытки `sprx` совпадают по времени с подозрительными RDP-переподключениями `wacsvc` — возможно это один и тот же злоумышленник.
 
---
 
## Ответы на вопросы
What is the Client Name of the system used to authenticate via the tdungan account (likely his home computer hostname)?
### 1. Client Name для аккаунта tdungan
 
```bash
grep -i "tdungan" sec.jsonl | grep -i "WorkstationName\|IpAddress" | head -20
```
 
**Ответ: `DUNGANATOR`**
 
Аккаунт `tdungan` подключался с компьютера `DUNGANATOR` по IP `172.16.30.8` и `172.16.30.3` через RDP (LogonType 10).
 
---
What suspicious account is recorded in RDP session reconnect events?

### 2. Подозрительный аккаунт в событиях RDP reconnect (Event 4778)
 
```bash
grep '"EventID":4778' sec.jsonl | grep -o '"AccountName":"[^"]*"' | sort | uniq -c | sort -rn
```
 
Результат:
```
7  "AccountName":"wacsvc"
5  "AccountName":"tdungan"
```
 
**Ответ: `wacsvc`**
 
Аккаунт `wacsvc` маскируется под системный сервис (Windows Admin Center Service), но используется для интерактивных RDP-сессий — это подозрительно.
 
---
On what days did the suspicious connections occur?
### 3. Дни подозрительных подключений
 
```bash
grep '"EventID":4778' sec.jsonl | grep "wacsvc" | grep -o '"SystemTime":"[^"]*"' | sort -u
```
 
Результат:
```
2023-01-18T14:50:19
2023-01-18T14:50:32
2023-01-18T15:26:40
2023-01-18T15:26:52
2023-01-18T20:32:07
2023-01-18T21:48:13
2023-01-19T14:28:14
```
 
**Ответ: `2023-01-18` и `2023-01-19`**
 
---
What Client Name and IP-address were in use for these connections? (4778)
### 4. Client Name и IP-адрес (Event 4778)
 
```bash
grep '"EventID":4778' sec.jsonl | grep -o '"ClientName":"[^"]*"\|"ClientAddress":"[^"]*"' | sort | uniq -c | sort -rn
```
 
Результат:
```
7  "ClientName":"phoenix"
7  "ClientAddress":"172.16.6.18"
```
 
**Ответ: ClientName = `phoenix`, IP = `172.16.6.18`**
 
---
There are hundreds of administrator authentications on this system, but using the custom column for 4672 events makes it feasible to quickly audit them. What domain accounts have authenticated to this system with admin-level privileges?
### 5. Доменные аккаунты с правами администратора (Event 4672)
 
```bash
grep '"EventID":4672' sec.jsonl | grep -o '"SubjectUserName":"[^"]*"' | sort | uniq -c | sort -rn | grep -v '"\$\|SYSTEM\|LOCAL\|ANONYM\|DWM\|NETWORK'
```
 
Результат:
```
107  "SubjectUserName":"rsydow-a"
 26  "SubjectUserName":"cbarton-a"
  9  "SubjectUserName":"wacsvc"
```
 
**Ответ: `rsydow-a` и `cbarton-a`**
 
Суффикс `-a` означает admin account — стандартная практика в корпоративных доменах для отдельных привилегированных аккаунтов.
 
---
 
## Итоговая таблица
 
| # | Вопрос | Ответ |
|---|--------|-------|
| 1 | Client Name для tdungan | **DUNGANATOR** |
| 2 | Подозрительный аккаунт в RDP reconnect | **wacsvc** |
| 3 | Дни подозрительных подключений | **2023-01-18 и 2023-01-19** |
| 4 | Client Name и IP (Event 4778) | **phoenix / 172.16.6.18** |
| 5 | Доменные аккаунты с правами админа | **rsydow-a, cbarton-a** |
 
---
 
## Вывод
 
Аккаунт `wacsvc` подключался по RDP с хоста `phoenix` (`172.16.6.18`) используя переподключение существующих сессий (Event 4778). Это характерно для техники **Session Hijacking** — злоумышленник переподключался к чужим RDP-сессиям без повторной аутентификации.
