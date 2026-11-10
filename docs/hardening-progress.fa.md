# شواهد اجرای فازها

## فاز ۰ — خط پایه

سند `hardening-baseline.fa.md` وضعیت اولیه، بازبینی commitها و نتیجهٔ آزمون‌ها را ثبت می‌کند. `uv.lock` و وابستگی‌ها بدون تغییرند.

## فاز ۱ — احراز هویت

اصلاح و آزموده شد: dependency مشترک مدیر روی routerهای legacy/admin/dashboard؛ اعتبارنامهٔ Bearer با رد قطعی توکن خالی/نامعتبر/عامل. Swagger قرارداد امنیت را نشان می‌دهد. `/health` جزئیات قبلی را برای مدیر حفظ می‌کند؛ `/healthz` پاسخ عمومی حداقلی دارد. ثبت‌نام و claim به مدیر وابسته نشده‌اند؛ سقف بدنهٔ ۶۴ KiB پیش از JSON parsing و محدودیت نرخ enroll اضافه شد.

ماتریس کامل مسیرها در `access-matrix.fa.md` است. معماری همچنان یک توکن مدیر با اختیار کامل دارد؛ سطح read/diagnostic/full طبقه‌بندی عملیات است، نه نقش‌های تازه. آزمون پیمایشی تمام مسیرهای محافظت‌شده و آزمون‌های موجود مالکیت Agent اجرا شدند.

فرمان آزمون: `uv run pytest tests/test_access_matrix.py tests/test_api.py tests/test_admin_api.py tests/test_agent_api.py tests/test_openapi_docs.py tests/test_dashboard_api.py tests/test_enrollment_request.py tests/test_console_api.py tests/test_e2e_enrollment.py -q`

نتیجه: **۱۲۷ موفق** در ۶۹٫۴۷ ثانیه، شامل جریان HTTP واقعی enrollment و Console روی loopback. در اجرای نخست، دو آزمون مستندات و healthcheck قدیمی E2E با تغییر قرارداد سازگار نبودند؛ dependency بدون پارامتر اضافی و healthcheck حداقلی اصلاح شد و اجرای نهایی کامل موفق بود. fixture بررسی‌های API نیز از اجرای واقعی ابزار شبکه جلوگیری می‌کند.

## فاز ۲ — Scope ابزارها

اصلاح و آزموده شد: مجوز مرکزی در `scope.py` و استفاده در registry، Ping/TCP در سطح collector، Nmap، fingerprint و reverse DNS. مسیرهای API و LLM همان کنترل را طی می‌کنند. هدف مشاهده‌شدهٔ investigation یا ورودی CLI به‌صورت خودکار مجوز نمی‌گیرد. شبکهٔ مشتق‌شده فقط برای discovery سبک مجاز است؛ پیکربندی مدیر جدا می‌ماند.

DNS فقط برای عملیات تک‌میزبان resolve می‌شود؛ تمام IPهای پاسخ باید مجاز باشند، سپس IP عددی بررسی‌شده به ابزار داده می‌شود تا تغییر DNS مقصد اجرا را عوض نکند. IPv4، IPv6، CIDR، mapped IPv6 و zone مربوط به link-local بررسی می‌شوند. Nmap همچنان ورودی IP/CIDR می‌گیرد. OFF بودن discovery دسترسی دستیِ تنظیم‌شده را حذف نمی‌کند.

فرمان: `uv run pytest tests/test_scope_enforcement.py tests/test_tool_validation.py tests/test_nmap_tools.py tests/test_agent_loop.py tests/test_fingerprint.py tests/test_api.py tests/test_discovery_policy.py -q`

نتیجه: **۱۵۲ موفق** در ۲٫۰۵ ثانیه. ۳۱ آزمون جدید شامل عدم اجرای شبکه در حالت رد مجوز، چند پاسخ DNS، IPv6 و مسیر واقعی Orchestrator با مدل جعلی است. تست TCP واقعی فقط loopback با مجوز صریح دارد؛ سایر عملیات شبکه mock هستند. اصلاح شمارش Ping و فرمان IPv6 Nmap طبق ترتیب مأموریت در فاز ۷ انجام می‌شود.

## فاز ۳ — ماندگاری Suricata

اصلاح و آزموده شد: Reader تا acknowledgment همان batch را نگه می‌دارد؛ Monitor رویداد، alert، host و cursor را در یک تراکنش می‌نویسد و فقط پس از commit تأیید می‌کند. خطای event/alert/cursor/commit کل batch را rollback می‌کند. `store_event` در خارج Monitor نیز اتمیک است. duplicate صرفاً با تضاد dedupe_key تشخیص داده می‌شود، نه با پنهان‌کردن تمام خطاهای IntegrityError.

restart از offset ذخیره‌شده است. هنگام rotation، descriptor قبلی ابتدا تخلیه می‌شود؛ در restart فایل هم‌خانوادهٔ EVE با inode/device قبلی جست‌وجو می‌شود. truncation کوتاه و truncation با رشد مجدد از طریق anchor نزدیک cursor تشخیص داده می‌شود. خط ناقص تا کامل‌شدن خوانده نمی‌شود. اگر فایل چرخیده دیگر قابل بازیابی نباشد، هشدار در log، meta و health باقی می‌ماند؛ دادهٔ فایلی که پیش از خواندن حذف شده قابل تضمین نیست. تضمین ingestion، **at-least-once همراه deduplication** است؛ ادعای exactly-once وجود ندارد.

Schema جدید لازم نبود؛ cursor قبلی با فیلدهای inode/offset همچنان خوانده می‌شود و device/anchor به JSON بعدی افزوده می‌شوند. تنظیم WAL تغییر نکرد. commitهای helperهای دیتابیس داخل تراکنش مشترک به تعویق می‌افتند؛ رفتار مستقل آن‌ها حفظ شده است.

آزمون هدفمند نخست: **۶۱ موفق**. سپس آزمون شکست commit و مرگ واقعی فرایند قبل commit اضافه شد. رگرسیون کامل `uv run pytest -q`: **۳۹۱ موفق، ۴ skipped** در ۷۵٫۵۴ ثانیه. آزمون‌های افزوده شامل append هنگام خاموشی، restart پس از شکست ذخیره، rotation در حالت روشن/خاموش، partial line، dedupe و rollback فرایند کشته‌شده‌اند.

## فاز ۴ — تحویل نتیجهٔ Endpoint

اصلاح و آزموده شد: در خود `endpoint_agent.py`، journal اجرای تسک و outbox SQLite اضافه شد. نتیجه پیش از ارسال روی دیسک می‌رود؛ فقط ACK منطبق با result_id/task_id/agent_id آن را حذف می‌کند. retry دارای backoff و سقف تأخیر است؛ نتیجهٔ تحویل‌نشده با گذشت زمان حذف نمی‌شود. نتیجهٔ اجرای قطع‌شده به‌صورت interrupted گزارش می‌شود و کار خودکار دوباره اجرا نمی‌شود. فایل 0600 در پوشهٔ 0700، خروجی محدود، صف محدود و tombstone اجرای قبلی حداقل تا انقضای تسک به‌علاوهٔ ۳۰ روز نگهداری می‌شود. تغییر فایل هویت نیز اتمیک شد.

worker اجرای تسک پیش‌فرض یک و حداکثر چهار است؛ تحویل نتیجه و لغو Console worker محدود و مستقل دارند. heartbeat با اجرای طولانی متوقف نمی‌شود. `control_only=true` فقط پیام لغو Console را می‌گیرد. SIGTERM مسیر shutdown را طی می‌کند؛ کارهای بومی در حال اجرا تا مهلت محدود خود فرصت پایان دارند و توقف ناگهانی از journal بازیابی می‌شود.

سرور با migration مستقل `001_agent_result_receipts` نتیجه و receipt را اتمیک ثبت می‌کند. درخواست تکراری با همان محتوا ACK مشابه می‌گیرد؛ تغییر محتوا با همان شناسه 409 است. درخواست عامل دیگر 403 است. نتیجهٔ دیررس در receipt حفظ می‌شود و وضعیت expired/cancelled تسک را عوض نمی‌کند؛ در جزئیات task قابل مشاهده است. API قدیمی بدون result_id قرارداد 409 قبلی را حفظ می‌کند. ACK جدید کوچک است و payload بزرگ screenshot را برنمی‌گرداند.

آزمون نهایی: `uv run pytest tests/test_endpoint_result_spool.py tests/test_agent_api.py tests/test_console_api.py tests/test_admin_api.py tests/test_screenshot.py tests/test_openapi_docs.py tests/test_e2e_enrollment.py -q`؛ **۹۸ موفق** در ۶۸٫۶۶ ثانیه، شامل HTTP واقعی، restart spool، قطع تحویل، ACK نادرست، تعارض شناسه، rollback خطای DB، heartbeat هنگام کار طولانی و migration تکرارپذیر. آزمون‌ها از این فاز حتی هنگام import برنامه نیز به دیتابیس موقت هدایت می‌شوند تا migration آزمایشی روی دادهٔ کاربر اجرا نشود.

## فاز ۵ — کلید مستقل و پروتکل امضا

اصلاح و آزموده شد: ریشهٔ تصادفی مستقل نسخهٔ ۲ فقط روی سرور؛ دریافت کلید مختص عامل از API دارای احراز هویت، بدون cache. Agent جدید `1.1.0` به master قدیمی نیاز ندارد. امضای HMAC استاندارد برای حفظ اسکریپت فقط-stdlib انتخاب شد؛ وابستگی جدیدی اضافه نشد. نسخه، key_id، زمان اجرا، IDها، نوع، پارامترها، expiry و nonce به امضا متصل‌اند. Agent جدید downgrade را رد می‌کند. deadline نسخهٔ ۱ ماندگار است و با restart تمدید نمی‌شود؛ تشخیص و inventory عامل قدیمی پس از deadline همچنان کار می‌کند.

آزمون تمیز بدون E2E: **۱۰۴ موفق** در ۸٫۶۰ ثانیه، شامل ۱۳ آزمون جدید کلید/امضا/مهاجرت. دو آزمون E2E HTTP نیز در اجرای همراه با آن‌ها موفق شدند و متغیر master از محیط Agent آزمون حذف شده است. آن اجرای نخست تنها یک انتظار نادرست 403 داشت: revocation در پیاده‌سازی موجود هش credential را باطل می‌کند و در نتیجه 401 درست است؛ انتظار آزمون اصلاح و دوباره موفق اجرا شد. کلید عامل دیگر و master قدیمی امضای نسخهٔ ۲ را جعل نمی‌کنند؛ rotation و replay آزموده شدند.

راهنمای استقرار و محدودیت امنیتی دورهٔ legacy در `task-signing.fa.md` آمده است. تنظیم سرویس سیستم یا کلید عامل‌های موجود خودکار تغییر نکرده؛ قطع کامل ریسک نسخهٔ ۱ نیازمند ارتقای آن عامل‌ها یا غیرفعال‌کردن legacy طبق راهنماست.

## فاز ۶ — ظرفیت و ماندگاری Job

اصلاح و آزموده شد: پیش‌فرض دو worker ثابت و صف ۳۲تایی؛ صف پر با HTTP 429 و Retry-After پاسخ می‌دهد. migration افزایشی `002_background_jobs` وضعیت و نتیجه را نگه می‌دارد. کارهای queued/running پس از restart به interrupted می‌روند؛ callableها خودکار دوباره اجرا نمی‌شوند. درخواست لغو دارای احراز هویت و Audit Log است. deadline و لغو بین مراحل بررسی کنترل و timeout عملیات بومی محدود می‌شود. thread جدید برای دورزدن timeout ساخته نمی‌شود؛ عملیات غیرهمکار تا بازگشت خود همان worker را اشغال می‌کند.

تاریخچهٔ Job حذف خودکار ندارد. رویدادها و raw eventها نیز سیاست حذف تازه‌ای نگرفته‌اند. retention قدیمی inventory (تعداد snapshot)، traffic (تعداد sample) و AI Activity (۱۰۰۰ رکورد) حفظ شد؛ برای نگهداری بلندمدت نیاز به سیاست آرشیو و حذف صریح مدیر وجود دارد. WAL و تنظیمات اصلی SQLite تغییر نکردند.

خطر واقعی دیگری در migration قدیمی رفع شد: جدول سالم `ai_memories` دیگر هنگام restart به نام legacy تغییر نمی‌کند. آزمون، باقی‌ماندن حافظهٔ تأییدشده در جدول فعال را پس از بازکردن دوبارهٔ دیتابیس بررسی می‌کند.

فرمان: `uv run pytest tests/test_jobs.py tests/test_api.py tests/test_database.py tests/test_ai_memory.py tests/test_openapi_docs.py tests/test_access_matrix.py tests/test_agent_loop.py tests/test_ai_activity.py -q`؛ **۱۱۸ موفق** در ۱۰٫۱۶ ثانیه. هشت آزمون جدید ظرفیت هم‌زمان، صف پر، لغو صف/اجرا، timeout همکار و غیرهمکار، restart، shutdown محدود و حفظ دانش را پوشش می‌دهند.

## فاز ۷ — تازگی Discovery

اصلاح و آزموده شد: `AUTO_DISCOVERY_TTL_SECONDS=900`، اعتبار مشاهده و آخرین Inventory، heartbeat تازه، enrollment فعال و رابط فعلی/up همگی شرط مجوز مشتق‌شده هستند. لغو عامل، تغییر subnet و حذف رابط فوراً اثر می‌گذارند؛ دادهٔ تاریخی و CIDRهای مدیر حذف یا تغییر نمی‌کنند. ذخیرهٔ Inventory و observation در یک تراکنش انجام می‌شود. projection دیتابیس اکنون زمان عددی مشاهده را نیز برمی‌گرداند.

آزمون: `uv run pytest tests/test_discovery_policy.py tests/test_discovery_freshness.py tests/test_agent_api.py tests/test_scope_enforcement.py -q`؛ **۷۱ موفق**. شکست اولیهٔ ۸ تست به حذف `last_epoch` از خروجی query مربوط بود؛ پس از رفع علت، تمام آزمون‌ها موفق شدند.

### Ping و IPv6

اصلاح و آزموده شد: شمارش پاسخ Ping از رکورد پاسخ (نه جمع TTL و time)، گزینه‌های Windows/Linux، Nmap discovery/services/OS و reverse DNS با `-6`، و رد IPv6 در arp-scan پیش از اجرا. reverse DNS در collector نیز کنترل Scope دارد. همهٔ عملیات فعال در این آزمون‌ها mock هستند، به‌جز آزمون اتصال محدود و مجاز loopback قبلی.

`uv run pytest tests/test_network_formats.py tests/test_tool_validation.py tests/test_nmap_tools.py tests/test_scope_enforcement.py tests/test_fingerprint.py -q`: **۱۰۸ موفق**.

تصحیح سابقهٔ آزمون: اجرای نخست ۱۰۸ تست موفق بود؛ افزودن کنترل داخل collector، با حذف کنترل قبلی registry، یک تست دفاع چندلایه را شکست داد (۱۰۷ موفق، یک ناموفق). خروجی با تأخیر خوانده شد و commit پیش از بررسی آن ثبت شد. بدون بازنویسی تاریخچه، کنترل registry نیز بازگردانده شد؛ اجرای نهایی مجدد **۱۰۸ موفق** در ۱٫۰۲ ثانیه بود.
