# شواهد اجرای فازها

## فاز ۰ — خط پایه

سند `hardening-baseline.fa.md` وضعیت اولیه، بازبینی commitها و نتیجهٔ آزمون‌ها را ثبت می‌کند. `uv.lock` و وابستگی‌ها بدون تغییرند.

## فاز ۱ — احراز هویت

اصلاح و آزموده شد: dependency مشترک مدیر روی routerهای legacy/admin/dashboard؛ اعتبارنامهٔ Bearer با رد قطعی توکن خالی/نامعتبر/عامل. Swagger قرارداد امنیت را نشان می‌دهد. `/health` جزئیات قبلی را برای مدیر حفظ می‌کند؛ `/healthz` پاسخ عمومی حداقلی دارد. ثبت‌نام و claim به مدیر وابسته نشده‌اند؛ سقف بدنهٔ ۶۴ KiB پیش از JSON parsing و محدودیت نرخ enroll اضافه شد.

ماتریس کامل مسیرها در `access-matrix.fa.md` است. معماری همچنان یک توکن مدیر با اختیار کامل دارد؛ سطح read/diagnostic/full طبقه‌بندی عملیات است، نه نقش‌های تازه. آزمون پیمایشی تمام مسیرهای محافظت‌شده و آزمون‌های موجود مالکیت Agent اجرا شدند.

فرمان آزمون: `uv run pytest tests/test_access_matrix.py tests/test_api.py tests/test_admin_api.py tests/test_agent_api.py tests/test_openapi_docs.py tests/test_dashboard_api.py tests/test_enrollment_request.py tests/test_console_api.py tests/test_e2e_enrollment.py -q`

نتیجه: **۱۲۷ موفق** در ۶۹٫۴۷ ثانیه، شامل جریان HTTP واقعی enrollment و Console روی loopback. در اجرای نخست، دو آزمون مستندات و healthcheck قدیمی E2E با تغییر قرارداد سازگار نبودند؛ dependency بدون پارامتر اضافی و healthcheck حداقلی اصلاح شد و اجرای نهایی کامل موفق بود. fixture بررسی‌های API نیز از اجرای واقعی ابزار شبکه جلوگیری می‌کند.
