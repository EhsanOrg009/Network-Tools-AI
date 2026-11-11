**تحویل مأموریت امنیت، پایداری و کنترل تحلیل AI — ۲۰۲۶-۱۱-۱۱**

اصلاحات قبلی حفظ و با رگرسیون کامل تأیید شدند. سه ایراد باقی‌مانده نیز بازتولید و اصلاح شد: عبور تسک اتصال Endpoint از Scope مرکزی، اعمال‌نشدن cooldown برای timeout مستقیم HTTPX در stream، و تکرار batch ناموفق به‌جای بازیابی تکی. تغییرات نیمه‌تمام رابط Security، ابزار بنچمارک و راهنمای فارسی تکمیل و commit شدند. محدودیت‌های سخت‌افزار و دورهٔ مهاجرت امضای قدیمی همچنان باید در استقرار در نظر گرفته شوند؛ این گزارش ادعای حذف همهٔ ریسک‌های عملیاتی ندارد.

**وضعیت ابتدا و حفظ کار قبلی**

شاخه `master` و مبنا `aa4962a` بود. ۲۵ commit اخیر بررسی شد. فازهای احراز هویت، Scope ابزارهای محلی، Suricata، spool عامل، امضای نسخهٔ ۲، JobManager، Discovery، Ping/IPv6/PCAP و کنترل Security قبلاً commit شده بودند؛ بازنویسی نشدند. معماری APIهای قدیمی/مدیر/عامل، ثبت‌نام و claim، Console، صف تسک، کلاینت مشترک LLM، دانش تأییدشده، پرسش، پیشنهاد اقدام و حسابرسی بازبینی شد.

در working tree اولیه، `README.fa.md`، `dashboard/src/pages/Security.tsx` و `scripts/benchmark_ollama.py` تغییر داشتند؛ `docs/benchmarks/ollama-validation.jsonl` و `run.txt` ثبت‌نشده بودند. تغییرات مرتبط با مأموریت حفظ، بررسی و در commitهای مرتبط ثبت شدند. `run.txt` خوانده، حذف، بازنویسی یا stage نشد.

خط پایهٔ تازه قبل از تغییر کد: `uv run pytest -q -rs` با **۴۹۵ موفق، ۴ skipped، بدون شکست** در ۱۲۹٫۱۱ ثانیه؛ `npm test` با **۲۹ موفق** و `npm run build` موفق. اختلاف با ۳۲۴ Backend و ۲۲ Dashboard تاریخی عمدتاً مربوط به آزمون‌های سخت‌سازی و کنترل AI موجود در commitهای قبلی است. هیچ آزمونی حذف یا ضعیف نشد.

**وضعیت هر بخش در تحویل**

| مورد | وضعیت | نتیجه و شاهد |
|---|---|---|
| ۱. وضعیت اولیه | بررسی‌شده | مبنای Git و فایل‌های تغییرکرده بالا ثبت شده‌اند؛ آزمون پایه شکست نداشت. |
| ۲. اصلاحات قبلی | از قبل درست؛ دوباره آزموده | فازهای commitشده در [گزارش فازها](hardening-progress.fa.md) و [ادامهٔ مأموریت](hardening-resume.fa.md) حفظ شدند. |
| ۳. ایرادهای موجود | نیازمند اصلاح بودند؛ اصلاح و آزموده | تست‌های تازه برای Scope/IPv6 عامل ابتدا ۸ شکست داشتند؛ تست timeout مستقیم و تست بازیابی batch نیز قبل از اصلاح شکست خوردند. |
| ۴. تغییرات این اجرا | اصلاح و آزموده | کنترل مقصد Endpoint در پذیرش و dispatch، IP تثبیت‌شده پس از DNS، IPv6 عامل، ورودی مقصد در UI، cooldown stream، retry تکی batch، برچسب فارسی وضعیت‌ها و گزارش بنچمارک. |
| ۵. احراز هویت API | از قبل درست؛ دوباره آزموده | guard مشترک Backend روی legacy/admin/dashboard، رد توکن خالی/نامعتبر/عامل، کنترل مالکیت منابع عامل. [ماتریس](access-matrix.fa.md) شامل ۷۷ مسیر تابعی به‌اضافهٔ OpenAPI و SPA است. |
| ۶. ToolScope | محلی از قبل درست؛ مسیر Endpoint اصلاح و آزموده | Ping، TCP، Nmap، arp-scan، fingerprint و reverse DNS کنترل مشترک دارند. تسک Endpoint نیز هنگام ایجاد و ارسال کنترل می‌شود؛ همهٔ پاسخ‌های DNS باید مجاز باشند. |
| ۷. Suricata | از قبل اصلاح‌شده؛ دوباره آزموده | ثبت event/alert/host/cursor در تراکنش مشترک، ACK پس از commit، deduplication، restart همراه append زمان خاموشی، rotation، truncation، partial line، خطای ذخیره و مرگ فرایند پیش از commit. تضمین هدف at-least-once است. |
| ۸. صف نتیجهٔ Endpoint | از قبل اصلاح‌شده؛ دوباره آزموده | SQLite محلی، result_id، ACK منطبق با عامل/تسک/نتیجه، backoff، تحویل تکراری بی‌اثر، journal اجرا و عدم اجرای مجدد پس از شکست تحویل. heartbeat از workerهای تسک جداست. |
| ۹. امضای مدیریتی | نسخهٔ ۲ درست و آزموده؛ نسخهٔ ۱ هنوز ریسک مهاجرت دارد | HMAC مستقل هر عامل، ریشهٔ جدید فقط روی سرور، پیوند امضا به پارامترها/هویت/نوع/مهلت/nonce/نسخه، رد downgrade و replay. [مهاجرت](task-signing.fa.md) با deadline ماندگار ۳۰روزه مستند است. |
| ۱۰. worker و Job | از قبل اصلاح‌شده؛ دوباره آزموده | ۲ worker و صف ۳۲تایی در تنظیم فعلی، 429 هنگام ظرفیت کامل، وضعیت ماندگار، cancel، timeout و shutdown محدود. کار قطع‌شده به interrupted می‌رود و کورکورانه تکرار نمی‌شود. |
| ۱۱. Auto Discovery | از قبل اصلاح‌شده؛ دوباره آزموده | TTL فعلی ۹۰۰ ثانیه، heartbeat و Inventory تازه، enrollment معتبر، عدم revocation، تطبیق رابط فعلی و subnet. خاموش‌کردن قابلیت، CIDR مدیر را حذف نمی‌کند. |
| ۱۲. IPv4/IPv6/Ping/PCAP | هسته از قبل درست؛ IPv6 عامل تکمیل و آزموده | شمارش رکورد پاسخ Windows/Linux، `-6` در Nmap، آدرس کامل/فشرده/mapped/link-local و CIDRها پوشش دارند. تست PCAP واقعاً TShark را روی capture ساختگی آفلاین اجرا کرد و skip نشد. |
| ۱۳. context واقعی Ollama | آزموده | CLI/سرور `0.40.15`، مدل دقیق `gemma-4-e4b:latest`؛ Modelfile بدون `num_ctx`، انتخاب runtime برابر 4096. ظرفیت آموزشی 131072 با context فعال یکسان نیست. |
| ۱۴. batch و timeout نهایی | انتخاب محافظه‌کارانه بر اساس آزمون | batch=1، تولید=600s، اتصال=5s، cooldown=60s، سقف خروجی=4096 و Structured Outputs روشن. `.env` کاربر تغییر نکرد. |
| ۱۵. نتایج Gemma واقعی | آزموده، با محدودیت روشن | این اجرا: تک‌هشدار، schema، length، ورودی بزرگ، timeout و worker دستی واقعی. آزمایش‌های batch=2/3، شواهد بزرگ، پاسخ مفصل و contextهای 6144/8192 در نتایج قبلی موجود و بازبینی‌شده‌اند؛ این دوره تکرار نشدند. جزئیات در [گزارش Ollama](ollama-validation.fa.md). |
| ۱۶. Auto Analysis | از قبل پیاده‌شده؛ دوباره آزموده | پیش‌فرض دیتابیس OFF، ماندگار پس از restart، تغییر فقط توسط مدیر با Audit Log؛ فقط رویدادهای تازهٔ واجد شرایط وارد intake می‌شوند. خاموش‌کردن صف قبلی را حذف نمی‌کند. |
| ۱۷. تحلیل دستی هر رویداد | از قبل پیاده‌شده؛ با مدل واقعی نیز آزموده | یک alert_id و job_id مستقل؛ کلیک تکراری همان کار/نتیجه را می‌دهد؛ retry شکست و reanalyze صریح جداست. نتیجهٔ قبلی در history محفوظ است. رویداد دیگر در تست واقعی تحلیل نشد. |
| ۱۸. شمار آزمون‌ها | موفق | رگرسیون نهایی **۵۰۹ موفق و ۴ skipped**؛ هر چهار مورد skipped از نوع opt-in بودند و جداگانه با مدل واقعی موفق شدند. پنج آزمون integration شامل پورت ناموجود، در دو اجرای ۴تایی و ۱تایی موفق شدند. Dashboard: **۲۹ موفق**. |
| ۱۹. build | موفق | TypeScript و Vite موفق؛ compileall کد Python نیز موفق. ابزار lint/type-check پایتون دیگری در پروژه تعریف نشده بود. هشدارهای غیرمسدودکنندهٔ React Router باقی‌اند. |
| ۲۰. Git | ثبت‌شده | commitهای مستقل در جدول پایین آمده‌اند؛ هیچ push، reset، clean، حذف commit یا commit دیتابیس/secret انجام نشد. |
| ۲۱. محدودیت‌ها | برخی همچنان عملیاتی؛ برخی آزموده‌نشده | فشار RAM/swap، legacy signing، محدودیت نگهداری فایل EVE، توقف مشارکتی threadها، نبود آرشیو تاریخی جامع و نبود آزمون میدانی Windows/تمام عامل‌های نصب‌شده در پایین توضیح داده شده‌اند. |
| ۲۲. working tree نهایی | بررسی در تحویل | تنها `?? run.txt` باقی می‌ماند؛ عمداً طبق دستور کاربر ثبت نشده است. سایر تغییرات مأموریت commit شده‌اند. هش commit حامل این گزارش در پاسخ نهایی و `git log` مشخص است. |
| ۲۳. uv و وابستگی‌ها | هماهنگ و بدون تغییر | `uv 0.11.23`، Python محیط `3.13.14`، `uv python list` و `uv sync --check` اجرا شدند: ۳۶ بسته هماهنگ و هیچ تغییر لازم نبود. تمام اجرای Python/pytest/compileall از uv بود؛ pip، محیط موازی یا وابستگی تازه استفاده نشد. `uv.lock`، `pyproject.toml` و lockfile npm بدون تغییرند. |

**رفتار Security و مرزهای دسترسی**

صفحهٔ `/dashboard/security` از هشدارهای ذخیره‌شدهٔ `/api/alerts` استفاده می‌کند. همهٔ شدت‌ها، از جمله شدت پایین و ناشناخته، واجد شرایط‌اند؛ اولویت فقط ترتیب را تعیین می‌کند. packet خام و payload ارتباطات خودکار به مدل ارسال نمی‌شود. flow/DNS/TLS خام خارج از جدول هشدار همچنان ذخیره می‌شوند؛ این مأموریت آن‌ها را به تعداد نامحدود درخواست AI تبدیل نکرده است.

تنظیم خودکار با `PUT /api/admin/v1/security-ai/automatic` و وضعیت آن با `GET /api/admin/v1/security-ai` در دسترس مدیر است. `POST /api/admin/v1/ai-analyses/{alert_id}/analyze` فقط همان هشدار را صف‌بندی می‌کند. `.../reanalyze` عملیات صریح مستقل و `.../history` مسیر نتیجه‌های پیشین است. APIها وجود رویداد، وضعیت، تکراری‌نبودن و ظرفیت را بررسی می‌کنند. API ناشناس یا اعتبارنامهٔ عامل اجازهٔ استفاده از این عملیات را ندارد.

مازاد خودکار در intake دیسکی حفظ و با ظرفیت محدود وارد پنجرهٔ پردازش می‌شود؛ درخواست دستی تازه در ظرفیت کامل 429 می‌گیرد. حالت خاموش مانع ذخیرهٔ رویداد نمی‌شود. هنگام قطع Ollama، خطا و وضعیت retry/failed واقعی نمایش داده می‌شود، حالت Auto تغییر نمی‌کند و تحلیل ناقص موفق محسوب نمی‌شود. شکست اتصال پس از برگشت مدل و probe موفق، با ظرفیت محدود بازیابی می‌شود؛ timeoutهای تمام‌کنندهٔ بودجه به retry صریح مدیر نیاز دارند. پردازش جدید batch پس از خطای provider به‌صورت تکی انجام می‌شود و این تصمیم از restart جان سالم می‌برد.

در هویت فعلی یک توکن مدیر با اختیار کامل وجود دارد. «Admin Read Only / Diagnostic / Full» در ماتریس طبقه‌بندی حساسیت عملیات است؛ ادعای وجود سه نقش مستقل نشده است. health عمومی فقط `/healthz` است؛ `/health` جزئیات حساس دارد و محافظت شده است. Swagger و OpenAPI عمومی، سیاست موجود را حفظ کرده‌اند. enrollment و claim به محدودیت اندازه/نرخ، اثبات هویت، تأیید مدیر، انقضا و مصرف یک‌باره متکی‌اند.

**شواهد رگرسیون و شکست‌های بازتولیدشده**

| اجرا | نتیجه |
|---|---|
| خط پایهٔ `uv run pytest -q -rs` | ۴۹۵ موفق، ۴ skipped؛ ۱۲۹٫۱۱ ثانیه |
| بازتولید تازهٔ Scope/IPv6 Endpoint | ابتدا ۸ شکست و ۳ موفق؛ سپس اصلاح |
| رگرسیون Scope، API عامل/مدیر، spool و امضا | ۱۰۵ موفق؛ ۴٫۹۵ ثانیه |
| بازتولید timeout مستقیم iterator | ابتدا یک شکست و ۷ موفق؛ پس از اصلاح موفق |
| بازتولید batch ناقص پس از restart | ابتدا شکست؛ پس از اصلاح تکی و بدون حذف رویداد موفق |
| مجموعهٔ هدفمند LLM/صف/اعتبارسنجی | ۶۷ موفق؛ ۳٫۲۱ ثانیه |
| integration واقعی اصلی Ollama | ۴ موفق؛ ۱۸۵٫۸۰ ثانیه |
| worker واقعی تحلیل دستی فقط یک رویداد | ۱ موفق؛ ۱۷۷٫۴۰ ثانیه |
| رگرسیون نهایی `uv run pytest -q -rs` | **۵۰۹ موفق، ۴ skipped؛ ۹۰٫۳۸ ثانیه** |
| `npm test` نهایی | **۲۹ موفق** در سه فایل |
| `npm run build` و `uv run python -m compileall ...` | موفق |
| `uv sync --check` و `git diff --check` | بدون تغییر لازم / بدون خطای whitespace |

تعداد کل Backend از ۴۹۹ به ۵۱۳ مورد رسید: ۱۱ مورد Scope/IPv6 عامل، یک timeout stream، یک بازیابی batch و یک integration دستی اضافه شدند. تفاوت تعداد موفق/skip همچنین شامل قابل‌دسترس‌شدن Ollama برای تست پورت ناموجود است. آزمون خارجیِ اسکن انجام نشد؛ شبکهٔ زنده فقط loopback مجاز و مدل محلی بود. PCAP آفلاین از دادهٔ TEST-NET ساختگی استفاده کرد. آزمون فیزیکیِ قطع برق/خرابی دیسک و اجرای میدانی Windows انجام نشده؛ شکست ذخیره و مرگ فرایند در محیط کنترل‌شده پوشش داده شد.

**Commitها**

| commit | پیام | جایگاه |
|---|---|---|
| `bbe9365` | `docs: record security hardening baseline and verified gaps` | خط پایهٔ قبلی |
| `1396b02` | `fix(api): enforce authentication across protected routes` | از قبل موجود؛ تأیید شد |
| `296f7a5` | `fix(security): enforce authorized scope for network tools` | از قبل موجود؛ تکمیل مسیر Endpoint |
| `2be433b` | `fix(suricata): make event ingestion restart-safe` | از قبل موجود؛ تأیید شد |
| `b99d140` | `fix(agent): persist task results until server acknowledgment` | از قبل موجود؛ تأیید شد |
| `1403f97` | `fix(security): isolate agent task signing credentials` | از قبل موجود؛ تأیید شد |
| `9edab55` | `fix(jobs): add bounded workers and durable job state` | از قبل موجود؛ تأیید شد |
| `68c25e5` | `fix(discovery): expire stale auto-discovered networks` | از قبل موجود؛ تأیید شد |
| `2fdf0cf` | `fix(network): correct ping counts and IPv6 support` | از قبل موجود؛ تکمیل IPv6 عامل |
| `369b55b` | `fix(security): preserve reverse DNS registry authorization` | از قبل موجود؛ تأیید شد |
| `8f30c81` | `fix(tools): repair and constrain offline PCAP analysis` | از قبل موجود؛ تأیید شد |
| `6f3ff57` | `fix(ollama): serialize generations and preserve structured output limits` | از قبل موجود؛ تکمیل timeout |
| `22eaf1a` | `feat(security): add durable automatic and per-alert AI analysis controls` | از قبل موجود؛ آزمون واقعی نیز موفق |
| `8eafdb8` | `fix(ai): reject repaired partial analyses and back off failed batches` | از قبل موجود؛ تأیید شد |
| `aa4962a` | `fix(ai): bound outage recovery and retain complete evidence identities` | مبنای این اجرا |
| `9652844` | `fix(security): enforce scope on endpoint connectivity tasks` | این اجرا |
| `ca3ee0a` | `fix(ollama): apply timeout cooldown to stalled streams` | این اجرا |
| `a5b2c63` | `fix(ai): retry failed batches as individual analyses` | این اجرا |
| `554ac73` | `test(ollama): record context limits and measured resource pressure` | این اجرا؛ شامل بنچمارک‌های قبلیِ ثبت‌نشده |
| `551bef1` | `fix(dashboard): label security analysis states in Persian` | این اجرا؛ تکمیل تغییر رابط موجود |

گزارش نهایی و README در commit مستقل مستندات ثبت شده‌اند. هیچ دادهٔ پایگاه داده، secret یا فایل `run.txt` داخل commitها نیست. مهاجرت‌های افزایشی قبلی `001_agent_result_receipts`، `002_background_jobs` و `003_security_ai_control` حفظ و در آزمون‌ها دوباره اجرا شدند؛ این اجرا schema تازه‌ای اضافه نکرد.

**محدودیت‌های باقی‌مانده**

- امضای نسخهٔ ۱ تا پایان مهاجرت خطر master مشترک دارد. عامل‌ها باید طبق راهنمای مهاجرت ارتقا یابند و سپس legacy غیرفعال شود. ارتقای میدانی عامل‌های کاربر و تغییر سرویس‌های آن‌ها انجام نشد. استفاده از HMAC مستقل به‌جای Ed25519 برای حفظ اسکریپت تک‌فایلی با کتابخانهٔ استاندارد است؛ ریشهٔ نسخهٔ ۲ مستقل از master قدیمی است.
- RAM/swap محدود همچنان روی تأخیر مدل اثر دارد. contextهای 6K/8K فقط نتایج آزمایشی موفق دارند و به تنظیم دائمی تبدیل نشدند. ورودی خیلی بزرگ ممکن است در Ollama بی‌آنکه API خطای صریح بدهد کوتاه شود. schema معتبر تضمین کیفیت استدلال امنیتی نیست؛ بررسی انسانی نتیجه لازم است.
- EVE چرخیده باید تا تخلیه در دسترس بماند؛ فایل حذف‌شده/بازنویسی‌شده پیش از خواندن قابل بازیابی نیست. خط ناقص تا کامل‌شدن نگه داشته می‌شود. ادعای exactly-once یا تحمل هر ترکیب دلخواهِ دیرنویسی و rotation وجود ندارد.
- توقف thread دلخواه در Python اجباری نیست؛ لغو مشارکتی است و ابزارهای بومی timeout دارند. thread مشغول جایگزین نامحدود نمی‌گیرد. برای workerهای AI این معماری، یک فرایند Uvicorn لازم است؛ استقرار چندپردازشیِ هماهنگ آزموده نشده است.
- صف intake خودکار برای حذف‌نشدن هشدار ظرفیت دیسکی مصرف می‌کند؛ اگر نرخ ورود از ظرفیت مدل بیشتر باشد backlog رشد می‌کند. سیاست حذف تازه‌ای برای رویدادهای تاریخی، raw event، Audit Log یا نتیجهٔ Job افزوده نشده است. retention قبلی inventory/traffic/AI Activity حفظ شده؛ آرشیو و حذف تاریخی باید با سیاست صریح مدیر انجام شود.
- مجوز 0600/0700 spool روی Linux آزموده شد؛ ACL سرویس Windows و مجموعهٔ کامل عامل‌های عملیاتی آزمون میدانی نشده‌اند. رابط با Vitest و build بررسی شد؛ آزمون دستی مرورگر روی دادهٔ عملیاتی انجام نشد.

**اجرا و تنظیمات**

```bash
uv sync
uv run netagent serve
```

Frontend از build موجود در `dashboard/dist` سرو می‌شود؛ برای بازسازی، در `dashboard` از `npm ci` و `npm run build` استفاده کنید. این اجرا چون وابستگی‌های موجود هماهنگ بودند نصب مجدد انجام نداد. Backend با تنظیم موجود و یک worker اجرا شود. `/dashboard/security` و `/api/docs` حفظ شده‌اند؛ برای داده‌های مدیریتی توکن مدیر لازم است. هیچ توکن نمونهٔ واقعی در این گزارش نیست.

Ollama باید جداگانه در آدرس تنظیم‌شده در دسترس باشد. فرایند موقتی که برای این آزمون‌ها اجرا شد پس از پایان کار متوقف شد؛ سرویس سیستم تغییر نکرد. قطع مدل مانع ذخیرهٔ رویداد نمی‌شود. راهنمای تنظیم و بنچمارک ترتیبی در [گزارش Ollama](ollama-validation.fa.md) و راهنمای عامل در [مهاجرت امضا](task-signing.fa.md) است.

وضعیت Git در تحویل:

```text
?? run.txt
```

این تنها فایل ثبت‌نشدهٔ عمدی است و طبق دستور کاربر دست‌نخورده باقی مانده است.
