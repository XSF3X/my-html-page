# خزنة الحسابات — Outlook وApple
تم إعداد الواجهة لتعمل ضمن مجلد `/outlook-cards-vault/` في المستودع `XSF3X/my-html-page`.

## الحالة
- مشروع Supabase أنشئ بنجاح باسم `outlook-account-vault` في منطقة Mumbai: `https://pheqddihzwnxvgsithus.supabase.co`.
- جداول `profiles` و`cards` منشأة، وRLS مفعّل، وتحقق مستشار الأمان من عدم وجود تنبيهات أمنية حالية.
- الواجهة تستخدم Supabase Publishable Key فقط؛ لا توجد مفاتيح server/service_role ضمن الملفات.
- يلزم إعداد مزوّد SMS في Supabase قبل أن يعمل تسجيل الدخول برسائل الجوال. هذه الخطوة تحتاج بيانات اعتماد المزوّد وقد تنطوي على تكلفة رسائل.

## النشر
1. من GitHub افتح `Settings → Pages` واجعل المصدر `GitHub Actions` إن لم يكن مضبوطًا مسبقًا.
2. سير العمل `.github/workflows/deploy-pages.yml` سينشر محتوى المستودع عند الدفع إلى `main`.
3. رابط الخزنة المتوقع: https://xsf3x.github.io/my-html-page/outlook-cards-vault/
4. بعد تفعيل SMS، اختبر إنشاء مستخدمين تجريبيين وتأكد أن كل مستخدم لا يرى إلا بطاقاته.
5. بعد تسجيل دخولك الأول، اجعل حسابك مديرًا من SQL Editor بهذه الطريقة:

```sql
select id, phone, display_name, role, created_at from public.profiles order by created_at desc;
update public.profiles set role = 'admin', updated_at = now() where id = 'UUID-OF-YOUR-USER';
```

## أمان
- البطاقات مشفّرة داخل المتصفح باستخدام AES-GCM ومفتاح مشتق عبر PBKDF2.
- عبارة الخزنة لا تُرسل إلى الخادم؛ إذا نسيتها لا يمكن فك تشفير النسخ.
- سجلات الإدارة تعرض المستخدمين فقط ولا تعرض محتوى البطاقات.
- لا تستخدم بيانات فعلية قبل إعداد SMS واختبار الفصل بين المستخدمين.
