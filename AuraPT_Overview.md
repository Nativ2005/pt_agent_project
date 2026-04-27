# AuraPT — Project Overview

> Air-gapped Web Penetration Testing CLI powered by local Ollama.

---

## מה זה AuraPT?

AuraPT הוא כלי CLI שרץ לגמרי **offline** (air-gapped) ומשתמש ב-**Ollama** (מודל שפה מקומי) כדי לנתח ממצאים מבדיקות חדירה (PT) של Web APIs.  
הרעיון: מזינים לו קבצי Burp Suite או Swagger, הוא מנתח אותם ושולח אותם למודל מקומי לקבלת תובנות — ללא תלות בענן.

---

## מבנה הפרויקט

```
pt_agent_project/
├── main.py                  # נקודת כניסה — CLI עם typer
├── requirements.txt         # תלויות Python
├── .gitignore
├── core/
│   ├── __init__.py
│   ├── models.py            # מודלי Pydantic (BurpRequest, SwaggerEndpoint)
│   └── ollama_client.py     # Async bridge ל-Ollama API המקומי
├── parsers/
│   ├── __init__.py
│   ├── burp_parser.py       # פרסור קבצי Burp Suite XML
│   └── swagger_parser.py    # פרסור קבצי OpenAPI / Swagger
└── tests/
    └── test_ollama_client.py  # Unit tests ל-OllamaClient
```

---

## קבצים — הסבר מפורט

### `requirements.txt`

```
typer[all]>=0.12.0
pydantic>=2.0
httpx>=0.27.0
pytest>=8.0
pytest-asyncio>=0.23
pytest-mock>=3.12
```

| ספרייה | מטרה |
|--------|-------|
| `typer` | בניית CLI נוח עם auto-complete ו-help אוטומטי |
| `pydantic` | ולידציה ו-typing קשיחה של הנתונים |
| `httpx` | HTTP client async-ready לתקשורת עם Ollama |
| `pytest` + `pytest-asyncio` | הרצת unit tests כולל async |
| `pytest-mock` | mocking נוח לטסטים |

---

### `main.py` — נקודת הכניסה

ה-CLI כולל שתי פקודות:

#### פקודה `scan`

| פרמטר | חובה? | ערכים | תיאור |
|-------|--------|-------|-------|
| `--env` | **חובה** | `dev` / `prod` | סביבת הרצה |
| `--burp` | אופציונלי | נתיב לקובץ | קובץ XML מיוצא מ-Burp Suite |
| `--swagger` | אופציונלי | נתיב לקובץ | קובץ OpenAPI/Swagger (JSON או YAML) |

```bash
python main.py scan --env dev --burp capture.xml
python main.py scan --env prod --swagger api.yaml
```

#### פקודה `test-connection`

בודקת שה-Ollama daemon פעיל ומציגה את המודלים הזמינים מקומית.

| פרמטר | ברירת מחדל | תיאור |
|-------|------------|-------|
| `--model` | `llama3` | המודל לבדיקה |
| `--host` | `http://localhost:11434` | כתובת Ollama |

```bash
python main.py test-connection
python main.py test-connection --model mistral --host http://localhost:11434
```

**פלט לדוגמה:**
```
[AuraPT] Pinging Ollama at http://localhost:11434 ...
  Ollama is UP  (version: 0.1.32)
[AuraPT] Fetching locally available models ...
  3 model(s) available:
   * llama3:latest
     mistral:latest
     codellama:latest
```

אם Ollama לא פעיל — מוצגת שגיאה בצבע אדום ו-exit code 1.

---

### `core/models.py` — מודלי Pydantic

#### `BurpRequest`
מייצג בקשת HTTP יחידה שחולצה מקובץ Burp XML.

```python
class BurpRequest(BaseModel):
    host: str               # לדוגמה: "api.example.com"
    path: str               # לדוגמה: "/api/v1/users"
    method: str             # GET, POST, PUT... (מנורמל אוטומטית ל-uppercase)
    headers: dict[str, str] # כל ה-headers של הבקשה
    body: str               # גוף הבקשה (ריק אם אין)
```

**ולידציות אוטומטיות:**
- `method` — מומר תמיד ל-uppercase
- `path` — מובטח שמתחיל ב-`/`

#### `SwaggerEndpoint`
מייצג endpoint יחיד שחולץ מ-Swagger/OpenAPI spec.

```python
class SwaggerEndpoint(BaseModel):
    base_url: str              # לדוגמה: "https://api.example.com/v1"
    path: str                  # לדוגמה: "/users/{id}"
    method: str                # GET, POST... (מנורמל ל-uppercase)
    operation_id: str | None   # שם הפעולה מה-spec
    parameters: list[str]      # שמות הפרמטרים
    summary: str | None        # תיאור קצר מה-spec

    @property
    def full_url(self) -> str  # מחזיר URL מלא: base_url + path
```

---

### `parsers/burp_parser.py` — פרסור Burp XML

פונקציה `parse_burp_xml(xml_path)` שעושה:

1. **פרסור XML** — קורא כל `<item>` בקובץ היצוא של Burp
2. **פענוח Base64** — Burp יכול לייצא בקשות מקודדות ב-base64, הפרסר מזהה ומפענח אוטומטית
3. **פיצול headers/body** — מפצל את בקשת ה-HTTP הגולמית לחלקיה
4. **סינון noise סטטי** — מסנן אוטומטית קבצים שלא רלוונטיים ל-PT:

```
.css .js .map .png .jpg .jpeg .gif .ico .svg
.woff .woff2 .ttf .eot .webp .avif .mp4 .webm .pdf
```

**פלט:** `list[BurpRequest]`

---

### `core/ollama_client.py` — Inference Bridge

מחלקה אסינכרונית `OllamaClient` שמהווה את הגשר בין הנתונים המפורסרים למודל המקומי.

**קונפיגורציה (ברירות מחדל):**

| פרמטר | ברירת מחדל | תיאור |
|-------|------------|-------|
| `model` | `llama3` | המודל שרץ ב-Ollama |
| `base_url` | `http://localhost:11434` | כתובת Ollama — localhost בלבד |
| `connect_timeout` | `5s` | timeout להתחברות |
| `read_timeout` | `120s` | timeout לקבלת תגובה |

**מתודות ציבוריות:**

```python
# בדיקת חיבור — מחזיר {"version": "0.1.32"} או זורק OllamaConnectionError
await client.ping() -> dict[str, str]

# ניתוח PT — מקבל system prompt + נתוני context, מחזיר string
await client.generate_analysis(system_prompt, context_data) -> str

# רשימת מודלים זמינים מקומית
await client.list_models() -> list[str]
```

**טיפול בשגיאות:**
- `OllamaConnectionError` — נזרקת אם `ollama serve` לא רץ, או אם פג ה-timeout
- כל token מגיע בזרם (streaming) ומחובר בסוף לתשובה מלאה

**דוגמת שימוש:**
```python
from core.ollama_client import OllamaClient, OllamaConnectionError

client = OllamaClient(model="llama3")
try:
    result = await client.generate_analysis(
        system_prompt="You are a web security expert. Identify vulnerabilities.",
        context_data="POST /api/login  Body: username=admin&password=1234",
    )
    print(result)
except OllamaConnectionError as e:
    print(f"Ollama not running: {e}")
```

---

### `tests/test_ollama_client.py` — Unit Tests

| טסט | מה בודק |
|-----|---------|
| `test_generate_analysis_returns_joined_tokens` | tokens מחוברים נכון |
| `test_generate_analysis_skips_empty_lines` | שורות ריקות מסוננות |
| `test_generate_analysis_raises_on_connect_error` | `OllamaConnectionError` על `ConnectError` |
| `test_generate_analysis_raises_on_read_timeout` | `OllamaConnectionError` על timeout |
| `test_default_url_points_to_localhost` | URL מצביע ל-localhost:11434 |
| `test_custom_base_url` | URL מותאם אישית |
| `test_model_is_stored` | שם המודל נשמר |

הרצת הטסטים:
```bash
pytest tests/ -v
```

---

### `parsers/swagger_parser.py` — פרסור Swagger/OpenAPI

פונקציה `parse_swagger_file(swagger_path)` שעושה:

1. **תמיכה בפורמטים:** JSON ו-YAML (YAML דורש `pip install pyyaml`)
2. **תמיכה בגרסאות:** OpenAPI 3 (`servers[]`) ו-Swagger 2 (`host` + `basePath`)
3. **חילוץ endpoints:** כל שילוב path + method עם הפרמטרים שלו

**HTTP methods שנאספים:** `GET POST PUT PATCH DELETE HEAD OPTIONS`

**פלט:** `list[SwaggerEndpoint]`

---

## Flow מלא

```
קובץ Burp XML          קובץ Swagger/OpenAPI
      │                        │
      ▼                        ▼
burp_parser.py         swagger_parser.py
      │                        │
      ▼                        ▼
 BurpRequest[]         SwaggerEndpoint[]
      │                        │
      └──────────┬─────────────┘
                 ▼
            main.py (CLI)
                 │
                 ▼
        OllamaClient.generate_analysis()
                 │
                 ▼
    http://localhost:11434/api/generate
                 │
                 ▼
         תגובת המודל (stream)
```

---

## מה חסר / השלבים הבאים

| שלב | סטטוס | תיאור |
|-----|--------|-------|
| `core/ollama_client.py` | ✅ הושלם | Async bridge ל-Ollama עם error handling |
| `tests/test_ollama_client.py` | ✅ הושלם | Unit tests מלאים עם mocking |
| Prompt templates | ⏳ בתור | בניית פרומפטים מ-BurpRequest / SwaggerEndpoint |
| `test-connection` command | ✅ הושלם | פינג ל-Ollama + רשימת מודלים ב-CLI |
| דוח פלט | ⏳ בתור | ייצוא ממצאים ל-JSON / Markdown |
| `--model` flag | ⏳ בתור | בחירת מודל Ollama (llama3, mistral, וכו') |
| טסטים לפרסרים | ⏳ בתור | unit tests ל-burp_parser ו-swagger_parser |

---

## התקנה מהירה

```bash
git clone https://github.com/Nativ2005/pt_agent_project.git
cd pt_agent_project
python -m venv .venv
.venv\Scripts\activate        # Windows
pip install -r requirements.txt
python main.py --help
```

**הרצת טסטים:**
```bash
pytest tests/ -v
```

**הרצה מלאה (עם Ollama פעיל):**
```bash
ollama serve                          # בטרמינל נפרד
ollama pull llama3
python main.py --env dev --burp capture.xml
```
