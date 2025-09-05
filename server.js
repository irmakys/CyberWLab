
const express = require('express');
const app = express();
const csrf = require('csurf');
const cookieParser = require('cookie-parser');

// CSRF middleware tanımı
const csrfProtection = csrf({ cookie: true });
app.use(cookieParser());
app.set('view engine', 'ejs');
app.set('views', './views');
app.use(express.static('public'));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// Test soruları ve doğru cevapları
const testQuestions = [
    {
        id: 1,
        question: "Bir web uygulamasında SSL sertifikası eksikse hangi saldırı riski artar?",
        options: ["A)Man-in-the-Middle (MITM)", "B) SQL Injection", "C) Brute Force"],
        correctAnswer: 0 // A şıkkı (index 0)
    },
    {
        id: 2,
        question: "Zayıf session yönetimi olan bir uygulamada saldırgan hangi yolu kullanarak kullanıcı hesabını ele geçirebilir?",
        options: ["A) Dosya MIME tipi değiştirme", "B)Session token tahmin etme", "C) CSP ekleme"],
        correctAnswer: 1 // B şıkkı (index 1)
    },
    {
        id: 3,
        question: "Kullanıcının oturum açmış olduğu sitede, saldırganın gizli bir form üzerinden istek göndermesi hangi açığı gösterir?",
        options: ["A) CSRF", "B) XSS", "C) Open Redirect"],
        correctAnswer: 0 // A şıkkı (index 0)
    },
    {
        id: 4,
        question: "Kullanıcıdan alınan veri HTML çıktısına eklenmeden önce sanitize edilmezse hangi saldırı mümkün olur?",
        options: ["A)Broken Access Control", "B)Cross-Site Scripting (XSS)", "C)Broken Access Control"],
        correctAnswer: 1 // B şıkkı (index 1)
    },
    {
        id: 5,
        question: "Login formunda kullanıcı girişi doğrulanmadan SQL sorgusuna eklenirse hangi risk vardır?",
        options: ["A) CSRF", "B)SQL Injection", "C)MIME Type exploit"],
        correctAnswer: 1 // B şıkkı (index 1)
    },
    {
        id: 6,
        question: "Bir kullanıcının başka kullanıcıların verilerine URL değiştirerek erişebilmesi hangi açığı işaret eder?",
        options: ["A) XSS", "B) IDOR / Broken Access Control", "C) CSRF"],
        correctAnswer: 1 // B şıkkı (index 1)
    },
    {
      id: 7,
      question: "Hangi header, clickjacking saldırılarını önler?",
      options: ["A) Content-Type", "B)Strict-Transport-Security", "C)X-Frame-Options"],
      correctAnswer: 2 // C şıkkı (index 2)
  },
  {
    id: 8,
    question: "CSP’nin “script-src 'self'” kuralı neyi sağlar?",
    options: ["A) Sadece kendi sunucundan gelen scriptlerin çalışmasını", "B)Tüm resimlerin yüklenmesini engeller", "C)HTTP üzerinden veri gönderir"],
    correctAnswer: 0 // A şıkkı (index 0)
},
{
  id: 9,
  question: "Kullanıcı yüklediği dosyanın extension ve MIME tipini kontrol etmezse saldırgan ne yapabilir?",
  options: ["A) Session token çalabilir", "B)Sunucuya zararlı PHP dosyası yükleyebilir", "C)CSP bypass yapamaz"],
  correctAnswer: 1 // B şıkkı (index 1)
},
{
  id: 10,
  question: "open redirect açığı hangi senaryoda ortaya çıkar?",
  options: ["A) Tarayıcı çökmesi", "B)Dosya boyutu artışı", "C)Kullanıcı bir linke tıkladığında farklı siteye yönlendirilir"],
  correctAnswer: 2 // C şıkkı (index 2)
},
{
  id: 11,
  question: "Brute force saldırılarını engellemek için hangi önlem alınır?",
  options: ["A) Rate limiting / throttling", "B)CSRF token", "C)Output encoding"],
  correctAnswer: 0 // A şıkkı (index 0)
},
{
  id: 12,
  question: "Tek bir şifreye dayalı login yerine MFA kullanmanın avantajı nedir?",
  options: ["A) ) Dosya yüklemeyi hızlandırır", "B)Hesap ele geçirilme riskini azaltır", "C)Tarayıcı önbelleğini temizler"],
  correctAnswer: 1 // B şıkkı (index 1)
},
{
  id: 13,
  question: "Bir form HTTPS üzerinden gönderilmiyorsa hangi risk yüksektir?",
  options: ["A) SQL injection", "B)Oturum çalınması (Session hijacking)", "C)File upload zafiyeti"],
  correctAnswer: 1 // B şıkkı (index 1)
},
{
  id: 14,
  question: "Hangi girdi doğrulama eksikliği saldırganın komut çalıştırmasına izin verir?",
  options: ["A) Command Injection", "B)CSRF", "C)Clickjacking"],
  correctAnswer: 0 // A şıkkı (index 0)
},
{
  id: 15,
  question: "Kullanıcı verisi HTML olarak gösterilmeden önce output encoding yapılmazsa ne olur?",
  options: ["A)XSS açığı", "B)Brute force atlatılır", "C)Open redirect oluşur"],
  correctAnswer: 0 // A şıkkı (index 0)
},
{
  id: 16,
  question: "HttpOnly ve Secure flag’leri olmayan cookie hangi saldırıya açıktır?",
  options: ["A)MIME Type bypass", "B)CSP bypass", "C)XSS ile çalınabilir"],
  correctAnswer: 2 // C şıkkı (index 2)
},
{
  id: 17,
  question: "Oturum süresi çok uzun belirlenirse hangi risk artar?",
  options: ["A)CSRF", "B)Session hijacking", "C)XSS"],
  correctAnswer: 1 // B şıkkı (index 1)
},{
  id: 18,
  question: "Zayıf login mantığı, saldırganın doğrudan admin paneline erişmesine neden olabilir. Bu hangi açığı gösterir?",
  options: ["A)Insecure Authentication", "B)Broken Access Control", "C)Open Redirect"],
  correctAnswer: 0 // A şıkkı (index 0)
},{
  id: 19,
  question: "HSTS header’ı neyi sağlar?",
  options: ["A)Dosya yüklemesini hızlandırır", "B)Brute force atlatılır", "C)Tarayıcıya sadece HTTPS ile bağlanmayı zorunlu kılar"],
  correctAnswer: 2 // C şıkkı (index 2)
},
{
  id: 20,
  question: "Bir form CSRF token kullanmıyor, output encoding uygulanmamış ve input validation zayıfsa hangi saldırılar mümkün olabilir?",
  options: ["ARate limiting bypass", "B)MIME Type exploit", "C)CSRF, XSS, SQL Injection"],
  correctAnswer: 2 // C şıkkı (index 2)
}
];

app.get('/', (req, res) => {
  res.render('anasayfa', { 
    username: 'Ajhushi',
    activePage: 'anasayfa'
  });
});

app.get('/roadmap', (req, res) => {
  res.render('roadmap', {
    activePage: 'harita'
  });
});

app.get('/road', (req, res) => {
  res.render('road', {
    activePage: 'road'
  });
});

app.get('/userpage', (req, res) => {
  res.render('userpage', { 
    username: 'yirmak',
    email: 'yirmak@gmail.com',
    registrationDate: '16.06.2025',
    activePage: 'profilim'
  });
});

app.get('/main', (req, res) => {
  res.render('main', {
    activePage: 'main'
  });
});

app.get('/test', (req, res) => {
  res.render('test', {
    activePage: 'test',
    questions: testQuestions,
    showResults: false
  });
});
app.get('/webSecurty', (req, res) => {
  res.render('webSecurty', {
    activePage: 'webSecurty'
  });
});

app.get('/xssTest', (req, res) => {
  res.render('xssTest', {
    activePage: 'xssTest'
  });
});

app.get('/sqlInjection', (req, res) => {
  res.render('sqlInjection', {
    activePage: 'sqlInjection'
  });
});

app.post('/test', (req, res) => {
  const userAnswers = req.body.answers || {};
  const results = [];
  let correctCount = 0;

  testQuestions.forEach(question => {
    const userAnswer = parseInt(userAnswers[question.id]);
    const isCorrect = userAnswer === question.correctAnswer;
    
    if (isCorrect) {
      correctCount++;
    }

    results.push({
      questionId: question.id,
      userAnswer: userAnswer,
      correctAnswer: question.correctAnswer,
      isCorrect: isCorrect
    });
  });

  const score = Math.round((correctCount / testQuestions.length) * 100);

  res.render('test', {
    activePage: 'test',
    questions: testQuestions,
    results: results,
    score: score,
    showResults: true
  });
});
// Insecure Login modülü için GET route
app.get('/insecure', csrfProtection, (req, res) => {
  // Başarısız giriş denemeleri session'da tutuluyor
  const attempts = req.session.loginAttempts || [];
  res.render('insecure', { csrfToken: req.csrfToken(), attempts });
});

// Login formu gönderimi - SESSION ve CSRF destekli
app.post('/test/insecure-login', csrfProtection, (req, res) => {
  const { username, password } = req.body;
  let error = null;
  let success = false;
  let infoLeak = '';    

  // SQL Injection zafiyeti: Kullanıcı adı ' OR '1'='1 gibi bir şeyse giriş başarılı
  if (username && username.includes("' OR '1'='1")) {
    req.session.user = username;
    success = true;
  } else {
    // Kullanıcıyı bul
    const user = users.find(u => u.username === username);
    if (!user) {
      error = `Kullanıcı bulunamadı! (Girdiğiniz kullanıcı adı: ${username})`;
      infoLeak = `Kullanıcı adı yanlış.`;
    } else if (user.password !== password) {
      error = `Şifre yanlış! (Girdiğiniz şifre: ${password})`;
      infoLeak = `Şifre yanlış, doğru kullanıcı adı: ${username}`;
    } else {
      req.session.user = username;
      success = true;
    }
  }

  // Başarısız giriş denemelerini session'da tut
  if (!success) {
    if (!req.session.loginAttempts) req.session.loginAttempts = [];
    req.session.loginAttempts.push({ username, password, error, infoLeak, time: new Date().toLocaleString() });
  } else {
    req.session.loginAttempts = [];
  }

  if (success) {
    return res.render('insecure', { csrfToken: req.csrfToken(), success: true, attempts: req.session.loginAttempts });
  } else {
    return res.render('insecure', { csrfToken: req.csrfToken(), error, infoLeak, attempts: req.session.loginAttempts });
  }
});

// Register formu gönderimi - CSRF koruması ile
app.post('/register', csrfProtection, (req, res) => {
  const { admin, password } = req.body;
  console.log('Kayıt denemesi:', admin, password);
  // Kayıt işlemi burada yapılacak
  res.redirect('/profilim');
});

// IDOR test sayfası
app.get('/idor', (req, res) => {
  res.render('idor', {
    activePage: 'idor'
  });
});

// Brute Force test sayfası
app.get('/brute', (req, res) => {
  res.render('brute', {
    activePage: 'brute'
  });
});

// File Upload test sayfası
app.get('/upload', (req, res) => {
  res.render('upload', {
    activePage: 'upload'
  });
});

app.listen(3001, () => console.log('http://localhost:3001 çalışıyor'));
