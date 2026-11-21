# ImkProject — Cloudflare Pages

Сайт сообщества ImkProject (GoreBox 27) с регистрацией, входом и Cloudflare Turnstile (CAPTCHA).

## Структура (всё в корне)

```
├── index.html              # Сайт + формы входа/регистрации
├── functions/
│   ├── _auth.js            # Серверная логика API
│   └── api/
│       ├── register.js     # POST /api/register
│       ├── login.js        # POST /api/login
│       ├── logout.js       # POST /api/logout
│       └── me.js           # GET  /api/me
├── schema.sql              # Таблицы D1
├── wrangler.toml
└── .gitignore
```

## Деплой на Cloudflare Pages через GitHub

1. Создай репозиторий на GitHub и загрузи **все файлы из этой папки** (чтобы `index.html` был в корне репозитория).

2. Cloudflare Dashboard → **Workers & Pages** → **Create** → **Pages** → **Connect to Git**

3. Настройки сборки:
   - **Framework preset:** None
   - **Build command:** *(оставь пустым)*
   - **Build output directory:** `/` или `.`

4. Создай D1 базу:
   ```bash
   npx wrangler d1 create imkproject-db
   ```
   Вставь `database_id` в `wrangler.toml`.

5. Выполни схему:
   ```bash
   npx wrangler d1 execute imkproject-db --remote --file=./schema.sql
   ```

6. В Pages → **Settings → Functions → D1 database bindings**:
   | Variable name | D1 database   |
   |---------------|---------------|
   | `DB`          | imkproject-db |

7. Turnstile:
   - Site Key → в `index.html` вместо `REPLACE_WITH_TURNSTILE_SITE_KEY`
   - Secret Key → Pages → Environment variables → **Secret** с именем `TURNSTILE_SECRET_KEY`

8. Redeploy.

## Безопасность

- Пароли: PBKDF2-SHA256, 310 000 итераций
- Сессии: в базе только SHA-256 хеш токена
- Cookie: HttpOnly + Secure + SameSite=Lax
- CAPTCHA проверяется на сервере

## Важно

- Не коммить `TURNSTILE_SECRET_KEY`
- Папка `functions` должна лежать в корне рядом с `index.html`
