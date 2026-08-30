// ================================================================
//  MainWindow.cpp  —  ECDAT Main Application Window
//  Clean, Fast, Developer-Centric UI (Codeforces Style)
//  Includes Multi-Language AST Discovery, Mosca Theorem, Multi-Format Export, & Scan History
// ================================================================

#include "../include/MainWindow.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QGridLayout>
#include <QHeaderView>
#include <QFileDialog>
#include <QMessageBox>
#include <QDateTime>
#include <QStyle>
#include <QMenuBar>
#include <QMenu>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <QStandardPaths>
#include <QClipboard>
#include <QApplication>
#include <QProcess>
#include <QDesktopServices>
#include <QUrl>
#include <QAction>
#include <QCursor>
#include <sstream>
#include <iomanip>

MainWindow::MainWindow(QWidget* parent) : QMainWindow(parent) {
    setWindowTitle("ECDAT — Enterprise Cryptographic Discovery & Assessment Tool");
    setWindowIcon(QIcon(":/icons/icon.png"));
    resize(1240, 840);
    setMinimumSize(960, 680);

    m_worker = new ScanWorker(this);
    connect(m_worker, &ScanWorker::progressUpdate,    this, &MainWindow::onProgress);
    connect(m_worker, &ScanWorker::findingDiscovered, this, &MainWindow::onFindingDiscovered);
    connect(m_worker, &ScanWorker::scanCompleted,     this, &MainWindow::onScanCompleted);
    connect(m_worker, &ScanWorker::errorOccurred,      this, &MainWindow::onScanError);

    setupUi();
    setupMenuBar();
    loadHistoryFromDisk();
    applyTheme(true); // Default: Obsidian Dark Mode
    updateMoscaDashboard();
}

MainWindow::~MainWindow() {
    saveHistoryToDisk();
    if (m_worker && m_worker->isRunning()) {
        m_worker->requestStop();
        m_worker->wait(2000);
    }
}

// ─────────────────────────────────────────────────────────────
//  MENU BAR SETUP
// ─────────────────────────────────────────────────────────────
void MainWindow::setupMenuBar() {
    QMenuBar* mb = menuBar();

    QMenu* fileMenu = mb->addMenu("File");
    fileMenu->addAction("📁 Open Folder to Scan…", QKeySequence::Open, this, &MainWindow::onBrowseFolderClicked);
    fileMenu->addAction("📄 Open Single File to Scan…", this, &MainWindow::onBrowseFileClicked);
    fileMenu->addSeparator();
    fileMenu->addAction("💾 Export CBOM / CSV / Report…", QKeySequence::Save, this, &MainWindow::onExportJsonClicked);
    fileMenu->addSeparator();
    fileMenu->addAction("Exit", QKeySequence::Quit, this, &QWidget::close);

    QMenu* viewMenu = mb->addMenu("View");
    viewMenu->addAction("🎯 Overview & Radar", this, [this]{ onTabButtonClicked(0); });
    viewMenu->addAction("📋 CBOM Inventory", this, [this]{ onTabButtonClicked(1); });
    viewMenu->addAction("🔍 Asset Inspector", this, [this]{ onTabButtonClicked(2); });
    viewMenu->addAction("🕒 Scan History", this, [this]{ onTabButtonClicked(3); });
    viewMenu->addSeparator();
    viewMenu->addAction("🌓 Toggle Dark / Light Theme", this, &MainWindow::onThemeToggled);

    QMenu* helpMenu = mb->addMenu("Help");
    helpMenu->addAction("📖 NIST PQC Standards (FIPS 203/204/205)", this, [this]{
        QMessageBox::information(this, "NIST PQC Standards",
            "NIST Post-Quantum Cryptography Standards (August 2024):\n\n"
            "• FIPS 203: ML-KEM (Module-Lattice Key Encapsulation / Kyber)\n"
            "• FIPS 204: ML-DSA (Module-Lattice Digital Signatures / Dilithium)\n"
            "• FIPS 205: SLH-DSA (Stateless Hash-Based Digital Signatures / SPHINCS+)\n\n"
            "ECDAT assesses vulnerabilities against Shor's Algorithm and recommends these replacements.");
    });
    helpMenu->addAction("🧮 Mosca's Theorem Reference", this, [this]{
        QMessageBox::information(this, "Mosca's Theorem Formula",
            "Mosca's Theorem: If (X + Y) > Z, data is vulnerable TODAY.\n\n"
            "• X = Data Secrecy Horizon (years needed to keep data confidential)\n"
            "• Y = Migration Timeline (years needed to transition to PQC)\n"
            "• Z = Quantum Horizon (years until a Cryptographically Relevant Quantum Computer arrives)\n\n"
            "Threat Scenario: Harvest-Now-Decrypt-Later (HNDL) attacks.");
    });
    helpMenu->addAction("ℹ️ About ECDAT", this, [this]{
        QMessageBox::about(this, "About ECDAT",
            "<b>ECDAT v1.0</b><br>"
            "Enterprise Cryptographic Discovery & Assessment Tool<br>"
            "Built for SIH / NTRO PQC Migration Strategy<br><br>"
            "Features multi-language AST inspection (C/C++, Python, Java, Go), Mosca's Theorem Risk Assessment, and CycloneDX CBOM Generation.");
    });
}

// ─────────────────────────────────────────────────────────────
//  THEME APPLICATION (Dynamic Light / Dark QSS)
// ─────────────────────────────────────────────────────────────
void MainWindow::applyTheme(bool isDark) {
    m_isDarkMode = isDark;
    QString qssPath = isDark ? ":/styles/ecdat_dark.qss" : ":/styles/ecdat_light.qss";
    QFile f(qssPath);
    if (f.open(QIODevice::ReadOnly | QIODevice::Text)) {
        qApp->setStyleSheet(f.readAll());
    }

    if (m_btnThemeToggle) {
        m_btnThemeToggle->setText(isDark ? "☀️ Light" : "🌙 Dark");
    }
    if (m_gauge) {
        m_gauge->setDarkMode(isDark);
    }
}

void MainWindow::onThemeToggled() {
    applyTheme(!m_isDarkMode);
    log(QString("Switched to %1 Mode").arg(m_isDarkMode ? "Dark" : "Light"), "#3182CE");
}

// ─────────────────────────────────────────────────────────────
//  UI INITIALIZATION
// ─────────────────────────────────────────────────────────────
void MainWindow::setupUi() {
    QWidget* central = new QWidget(this);
    setCentralWidget(central);
    QVBoxLayout* rootLayout = new QVBoxLayout(central);
    rootLayout->setContentsMargins(0, 0, 0, 0);
    rootLayout->setSpacing(0);

    // 1. Top Header Bar
    rootLayout->addWidget(buildHeaderBar());

    // 2. Stacked Multi-Tab View
    m_stackedPages = new QStackedWidget;
    m_stackedPages->setObjectName("mainStackedWidget");
    m_stackedPages->addWidget(buildDashboardTab()); // Index 0
    m_stackedPages->addWidget(buildCbomTab());      // Index 1
    m_stackedPages->addWidget(buildDetailTab());    // Index 2
    m_stackedPages->addWidget(buildHistoryTab());   // Index 3
    rootLayout->addWidget(m_stackedPages, 1);

    // 3. Bottom Terminal & Log Dock
    rootLayout->addWidget(buildBottomBar());

    m_tableModel = new CbomTableModel(this);
    if (m_tableView) {
        m_tableView->setModel(m_tableModel);
    }
}

// ─────────────────────────────────────────────────────────────
//  HEADER BAR: Codeforces Clean Layout
// ─────────────────────────────────────────────────────────────
QWidget* MainWindow::buildHeaderBar() {
    QWidget* header = new QWidget;
    header->setObjectName("headerBar");
    header->setFixedHeight(50);

    QHBoxLayout* hl = new QHBoxLayout(header);
    hl->setContentsMargins(16, 0, 16, 0);
    hl->setSpacing(12);

    // Brand Text Logo (textlogo.png)
    QLabel* brandLogo = new QLabel;
    brandLogo->setObjectName("brandLogo");
    QPixmap logoPix(":/icons/textlogo.png");
    if (!logoPix.isNull()) {
        brandLogo->setPixmap(logoPix.scaledToHeight(28, Qt::SmoothTransformation));
    } else {
        brandLogo->setText("<span style='font-size:15px;font-weight:900;color:#38BDF8;'>ECDAT</span>");
    }
    hl->addWidget(brandLogo);

    hl->addSpacing(8);

    // Navigation Switcher
    QWidget* navGroup = new QWidget;
    navGroup->setObjectName("navGroup");
    QHBoxLayout* nl = new QHBoxLayout(navGroup);
    nl->setContentsMargins(2, 2, 2, 2);
    nl->setSpacing(2);

    m_btnNavDash = new QPushButton(" Overview & Radar ");
    m_btnNavDash->setObjectName("navPill");
    m_btnNavDash->setCheckable(true);
    m_btnNavDash->setChecked(true);
    connect(m_btnNavDash, &QPushButton::clicked, this, [this]{ onTabButtonClicked(0); });
    nl->addWidget(m_btnNavDash);

    m_btnNavCbom = new QPushButton(" CBOM Inventory ");
    m_btnNavCbom->setObjectName("navPill");
    m_btnNavCbom->setCheckable(true);
    connect(m_btnNavCbom, &QPushButton::clicked, this, [this]{ onTabButtonClicked(1); });
    nl->addWidget(m_btnNavCbom);

    m_btnNavDetail = new QPushButton(" Asset Inspector ");
    m_btnNavDetail->setObjectName("navPill");
    m_btnNavDetail->setCheckable(true);
    connect(m_btnNavDetail, &QPushButton::clicked, this, [this]{ onTabButtonClicked(2); });
    nl->addWidget(m_btnNavDetail);

    m_btnNavHistory = new QPushButton(" Scan History ");
    m_btnNavHistory->setObjectName("navPill");
    m_btnNavHistory->setCheckable(true);
    connect(m_btnNavHistory, &QPushButton::clicked, this, [this]{ onTabButtonClicked(3); });
    nl->addWidget(m_btnNavHistory);

    hl->addWidget(navGroup);

    hl->addStretch(1);

    // Sun / Moon Dark Mode Toggle Button
    m_btnThemeToggle = new QPushButton(m_isDarkMode ? "☀️ Light" : "🌙 Dark");
    m_btnThemeToggle->setObjectName("btnThemeToggle");
    m_btnThemeToggle->setFixedHeight(30);
    m_btnThemeToggle->setToolTip("Toggle between Light and Dark Mode (Sun/Moon)");
    connect(m_btnThemeToggle, &QPushButton::clicked, this, &MainWindow::onThemeToggled);
    hl->addWidget(m_btnThemeToggle);

    hl->addSpacing(4);

    // Export Button (always clickable with multi-format support)
    m_exportBtn = new QPushButton("💾 Export CBOM");
    m_exportBtn->setObjectName("btnHeaderExport");
    m_exportBtn->setFixedHeight(30);
    connect(m_exportBtn, &QPushButton::clicked, this, &MainWindow::onExportJsonClicked);
    hl->addWidget(m_exportBtn);

    // Status Indicator
    m_headerStatus = new QLabel("● Ready");
    m_headerStatus->setObjectName("statusReady");
    m_headerStatus->setFixedHeight(28);
    hl->addWidget(m_headerStatus);

    return header;
}

// ─────────────────────────────────────────────────────────────
//  DASHBOARD TAB: Overview & Mosca Theorem Interactive Grid
// ─────────────────────────────────────────────────────────────
QWidget* MainWindow::buildDashboardTab() {
    QScrollArea* scroll = new QScrollArea;
    scroll->setWidgetResizable(true);
    scroll->setFrameShape(QFrame::NoFrame);
    scroll->setObjectName("pageScrollArea");

    QWidget* page = new QWidget;
    page->setObjectName("dashContainer");
    QVBoxLayout* vl = new QVBoxLayout(page);
    vl->setContentsMargins(16, 14, 16, 14);
    vl->setSpacing(12);

    // ── Row 1: Summary Metric Cards ───────────────────────────
    QHBoxLayout* heroRow = new QHBoxLayout;
    heroRow->setSpacing(10);

    auto makeHeroCard = [&](const QString& title, const QString& sub, QLabel*& countLabel, const QString& objName) {
        QWidget* card = new QWidget;
        card->setObjectName(objName);
        card->setFixedHeight(74);

        QVBoxLayout* cl = new QVBoxLayout(card);
        cl->setContentsMargins(12, 8, 12, 8);
        cl->setSpacing(2);

        QHBoxLayout* th = new QHBoxLayout;
        QLabel* titleLbl = new QLabel(title);
        titleLbl->setStyleSheet("font-size:11px;font-weight:700;background:transparent;");
        th->addWidget(titleLbl);
        th->addStretch();

        countLabel = new QLabel("0");
        countLabel->setObjectName("heroCount");
        th->addWidget(countLabel);
        cl->addLayout(th);

        QLabel* subLbl = new QLabel(sub);
        subLbl->setStyleSheet("font-size:9px;color:#64748B;background:transparent;");
        cl->addWidget(subLbl);

        heroRow->addWidget(card, 1);
    };

    makeHeroCard("Critical Vulnerabilities", "Broken by Shor's Algo (RSA, ECC, DH)", m_statCritCount,  "heroCardCrit");
    makeHeroCard("Moderate Risk Assets",     "Grover's Key Weakening (AES-128, 3DES)", m_statModCount,   "heroCardMod");
    makeHeroCard("Quantum-Safe Assets",      "Post-Quantum Ready (AES-256, PQC)",      m_statSafeCount,  "heroCardSafe");
    makeHeroCard("Total Discovered Assets",  "Discovered across target architecture",  m_statTotalCount, "heroCardTotal");

    vl->addLayout(heroRow);

    // ── Row 2: Two-Column Clean Grid ──────────────────────────
    QHBoxLayout* centerGrid = new QHBoxLayout;
    centerGrid->setSpacing(12);

    // ── Left Column (46%): Scanner Setup & Mosca Theorem ──────
    QVBoxLayout* leftCol = new QVBoxLayout;
    leftCol->setSpacing(12);

    // Card 1: Target Controller (Compact & Tight)
    QWidget* scanCard = new QWidget;
    scanCard->setObjectName("slateCard");
    scanCard->setSizePolicy(QSizePolicy::Preferred, QSizePolicy::Fixed);
    QVBoxLayout* scVL = new QVBoxLayout(scanCard);
    scVL->setContentsMargins(14, 12, 14, 12);
    scVL->setSpacing(8);
    scVL->setAlignment(Qt::AlignTop);

    QLabel* scTitle = new QLabel("Target Repository & Audit Configuration");
    scTitle->setObjectName("cardHeader");
    scVL->addWidget(scTitle);

    QHBoxLayout* targetRow = new QHBoxLayout;
    targetRow->setSpacing(6);
    m_targetEdit = new QLineEdit;
    m_targetEdit->setPlaceholderText("Select directory or file to audit (e.g. /path/to/source)...");
    m_targetEdit->setObjectName("inputPath");
    targetRow->addWidget(m_targetEdit, 1);

    m_browseBtn = new QPushButton("📁 Folder…");
    m_browseBtn->setObjectName("btnBrowse");
    connect(m_browseBtn, &QPushButton::clicked, this, &MainWindow::onBrowseFolderClicked);
    targetRow->addWidget(m_browseBtn);

    m_browseFileBtn = new QPushButton("📄 File…");
    m_browseFileBtn->setObjectName("btnBrowseFile");
    connect(m_browseFileBtn, &QPushButton::clicked, this, &MainWindow::onBrowseFileClicked);
    targetRow->addWidget(m_browseFileBtn);
    scVL->addLayout(targetRow);

    QHBoxLayout* optsRow = new QHBoxLayout;
    optsRow->setSpacing(16);
    m_cbSource = new QCheckBox("AST Code Parser");
    m_cbSource->setToolTip("Scan C/C++, Python, Java, and Go source code via AST analysis");
    m_cbSource->setChecked(true);
    optsRow->addWidget(m_cbSource);

    m_cbBinary = new QCheckBox("Binary Signatures");
    m_cbBinary->setToolTip("Scan compiled binaries and shared libraries for cryptographic algorithms");
    m_cbBinary->setChecked(true);
    optsRow->addWidget(m_cbBinary);

    m_cbCert = new QCheckBox("Certs & Configs");
    m_cbCert->setToolTip("Scan X.509 PEM certificates, keys, and TLS configuration files");
    m_cbCert->setChecked(true);
    optsRow->addWidget(m_cbCert);
    optsRow->addStretch();
    scVL->addLayout(optsRow);

    QHBoxLayout* projRow = new QHBoxLayout;
    projRow->setSpacing(8);
    QLabel* prLbl = new QLabel("Project Tag:");
    prLbl->setStyleSheet("font-size:11px;color:#64748B;font-weight:600;background:transparent;");
    projRow->addWidget(prLbl);
    m_projectEdit = new QLineEdit("Core Crypto Infrastructure");
    m_projectEdit->setObjectName("inputProject");
    projRow->addWidget(m_projectEdit, 1);

    m_startBtn = new QPushButton("⚡ Run Full Audit");
    m_startBtn->setObjectName("btnStartScan");
    m_startBtn->setFixedHeight(32);
    connect(m_startBtn, &QPushButton::clicked, this, &MainWindow::onStartScanClicked);
    projRow->addWidget(m_startBtn);

    m_stopBtn = new QPushButton("⏹ Stop");
    m_stopBtn->setObjectName("btnStopScan");
    m_stopBtn->setFixedHeight(32);
    m_stopBtn->setEnabled(false);
    connect(m_stopBtn, &QPushButton::clicked, this, &MainWindow::onStopScanClicked);
    projRow->addWidget(m_stopBtn);
    scVL->addLayout(projRow);

    leftCol->addWidget(scanCard, 0);

    // Card 2: Mosca's Theorem Interactive Matrix & Formula
    QWidget* moscaCard = new QWidget;
    moscaCard->setObjectName("slateCard");
    QVBoxLayout* mcVL = new QVBoxLayout(moscaCard);
    mcVL->setContentsMargins(14, 12, 14, 12);
    mcVL->setSpacing(8);

    QHBoxLayout* mth = new QHBoxLayout;
    QLabel* mcTitle = new QLabel("Mosca's Theorem: Quantum Exposure Horizon");
    mcTitle->setObjectName("cardHeader");
    mth->addWidget(mcTitle);
    mth->addStretch();
    QLabel* formulaTag = new QLabel("Formula: If (X + Y) > Z → RED ALERT");
    formulaTag->setStyleSheet("font-size:10px;font-weight:700;color:#3182CE;background:transparent;");
    mth->addWidget(formulaTag);
    mcVL->addLayout(mth);

    // Formula Dynamic Calculation Box
    QFrame* formulaBox = new QFrame;
    formulaBox->setStyleSheet("background:#F8FAFC;border:1px solid #E2E8F0;border-radius:4px;padding:6px;");
    QVBoxLayout* fbVL = new QVBoxLayout(formulaBox);
    fbVL->setContentsMargins(8, 6, 8, 6);
    fbVL->setSpacing(3);

    m_moscaFormulaLabel = new QLabel("(X: 15 yrs) + (Y: 3 yrs) = 18 yrs vs (Z: 10 yrs)");
    m_moscaFormulaLabel->setStyleSheet("font-size:11px;font-weight:800;color:#0F172A;background:transparent;");
    fbVL->addWidget(m_moscaFormulaLabel);

    m_moscaMarginLabel = new QLabel("🔴 Threat Horizon: -8.0 yrs Deficit (Harvest-Now-Decrypt-Later Threat Active)");
    m_moscaMarginLabel->setStyleSheet("font-size:10px;font-weight:700;color:#EF4444;background:transparent;");
    fbVL->addWidget(m_moscaMarginLabel);

    mcVL->addWidget(formulaBox);

    auto makeMoscaSlider = [&](const QString& title, const QString& desc, int min, int max, int defaultVal, QSlider*& slider, QLabel*& valLabel, const QString& colorHex) {
        QHBoxLayout* rowHdr = new QHBoxLayout;
        QLabel* nLbl = new QLabel(title);
        nLbl->setStyleSheet("font-size:11px;font-weight:700;background:transparent;");
        valLabel = new QLabel(QString::number(defaultVal) + " yrs");
        valLabel->setStyleSheet(QString("font-size:10px;font-weight:800;color:%1;background:transparent;").arg(colorHex));
        rowHdr->addWidget(nLbl);
        rowHdr->addStretch();
        rowHdr->addWidget(valLabel);
        mcVL->addLayout(rowHdr);

        QLabel* dLbl = new QLabel(desc);
        dLbl->setStyleSheet("font-size:9px;color:#64748B;background:transparent;");
        mcVL->addWidget(dLbl);

        slider = new QSlider(Qt::Horizontal);
        slider->setRange(min, max);
        slider->setValue(defaultVal);
        slider->setObjectName("moscaSlider");
        connect(slider, &QSlider::valueChanged, this, [valLabel, this](int v){
            valLabel->setText(QString::number(v) + " yrs");
            onMoscaChanged();
        });
        mcVL->addWidget(slider);
        mcVL->addSpacing(2);
    };

    makeMoscaSlider("X — Data Secrecy Lifetime", "How long must encrypted assets remain confidential?", 1, 30, 15, m_sliderX, m_labelX, "#EF4444");
    makeMoscaSlider("Y — PQC Migration Timeline", "Time required to transition system architecture to NIST PQC", 1, 10,  3, m_sliderY, m_labelY, "#F59E0B");
    makeMoscaSlider("Z — CRQC Quantum Arrival", "Estimated years until Cryptographically Relevant Quantum Computer", 3, 25, 10, m_sliderZ, m_labelZ, "#10B981");

    leftCol->addWidget(moscaCard);
    centerGrid->addLayout(leftCol, 46);

    // ── Right Column (54%): Threat Dial & Distribution ────────
    QVBoxLayout* rightCol = new QVBoxLayout;
    rightCol->setSpacing(12);

    // Card 3: Threat Meter Dial
    QWidget* radarCard = new QWidget;
    radarCard->setObjectName("slateCard");
    QVBoxLayout* rcVL = new QVBoxLayout(radarCard);
    rcVL->setContentsMargins(14, 12, 14, 12);
    rcVL->setSpacing(6);

    QLabel* rcTitle = new QLabel("Quantum Threat Index & Advisory");
    rcTitle->setObjectName("cardHeader");
    rcTitle->setAlignment(Qt::AlignCenter);
    rcVL->addWidget(rcTitle);

    m_gauge = new RiskGaugeWidget(radarCard);
    m_gauge->setMinimumHeight(200);
    m_gauge->setDarkMode(m_isDarkMode);
    m_gauge->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
    rcVL->addWidget(m_gauge, 1);

    m_moscaBadge = new QLabel("RED ALERT — IMMEDIATE PQC MIGRATION REQUIRED");
    m_moscaBadge->setObjectName("verdictCrit");
    m_moscaBadge->setAlignment(Qt::AlignCenter);
    rcVL->addWidget(m_moscaBadge);

    m_moscaDesc = new QLabel("X + Y (18 yrs) > Z (10 yrs): Harvest-Now-Decrypt-Later vulnerability active.");
    m_moscaDesc->setObjectName("verdictDesc");
    m_moscaDesc->setAlignment(Qt::AlignCenter);
    m_moscaDesc->setWordWrap(true);
    rcVL->addWidget(m_moscaDesc);

    rightCol->addWidget(radarCard, 56);

    // Card 4: Cryptographic Family Distribution
    QWidget* distroCard = new QWidget;
    distroCard->setObjectName("slateCard");
    QVBoxLayout* dcVL = new QVBoxLayout(distroCard);
    dcVL->setContentsMargins(14, 10, 14, 10);
    dcVL->setSpacing(6);

    QLabel* dcTitle = new QLabel("Cryptographic Family Distribution");
    dcTitle->setObjectName("cardHeader");
    dcVL->addWidget(dcTitle);

    static const struct { const char* name; const char* color; } families[] = {
        { "Asymmetric Public Key (RSA / ECC / ECDH)", "#EF4444" },
        { "Legacy Symmetric (DES / 3DES / RC4)",      "#F97316" },
        { "Legacy Hash Functions (MD5 / SHA-1)",      "#F59E0B" },
        { "Standard Symmetric (AES-128 / GCM)",        "#3B82F6" },
        { "Quantum-Resistant (AES-256 / SHA-3 / PQC)", "#10B981" }
    };

    for (int i = 0; i < 5; ++i) {
        QHBoxLayout* row = new QHBoxLayout;
        row->setSpacing(8);

        QLabel* nameLbl = new QLabel(families[i].name);
        nameLbl->setFixedWidth(240);
        nameLbl->setStyleSheet("font-size:10px;font-weight:600;background:transparent;");
        row->addWidget(nameLbl);

        m_algoBars[i] = new QProgressBar;
        m_algoBars[i]->setRange(0, 100);
        m_algoBars[i]->setValue(0);
        m_algoBars[i]->setTextVisible(false);
        m_algoBars[i]->setFixedHeight(6);
        m_algoBars[i]->setStyleSheet(
            QString("QProgressBar { background:#CBD5E1; border:none; border-radius:3px; }"
                    "QProgressBar::chunk { background:%1; border-radius:3px; }").arg(families[i].color));
        row->addWidget(m_algoBars[i], 1);

        m_algoCounts[i] = new QLabel("0");
        m_algoCounts[i]->setFixedWidth(30);
        m_algoCounts[i]->setAlignment(Qt::AlignRight);
        m_algoCounts[i]->setStyleSheet("font-size:10px;font-weight:700;color:#64748B;background:transparent;");
        row->addWidget(m_algoCounts[i]);

        dcVL->addLayout(row);
    }

    rightCol->addWidget(distroCard, 44);
    centerGrid->addLayout(rightCol, 54);
    vl->addLayout(centerGrid, 1);

    scroll->setWidget(page);
    return scroll;
}

// ─────────────────────────────────────────────────────────────
//  CBOM TAB: Codeforces Submission-Style High-Contrast Table
// ─────────────────────────────────────────────────────────────
QWidget* MainWindow::buildCbomTab() {
    QWidget* page = new QWidget;
    page->setObjectName("cbomPage");
    QVBoxLayout* vl = new QVBoxLayout(page);
    vl->setContentsMargins(16, 12, 16, 12);
    vl->setSpacing(10);

    // Table Header Toolbar
    QHBoxLayout* bar = new QHBoxLayout;
    bar->setSpacing(10);

    QLabel* tableTitle = new QLabel("Cryptographic Bill of Materials (CBOM)");
    tableTitle->setObjectName("cardHeader");
    bar->addWidget(tableTitle);

    m_tableStats = new QLabel("0 assets discovered");
    m_tableStats->setStyleSheet("font-size:11px;color:#64748B;font-weight:600;background:transparent;");
    bar->addWidget(m_tableStats);

    bar->addStretch();

    m_filterEdit = new QLineEdit;
    m_filterEdit->setPlaceholderText("🔍 Filter by algorithm, file, risk, or CWE...");
    m_filterEdit->setObjectName("filterEdit");
    m_filterEdit->setFixedWidth(280);
    connect(m_filterEdit, &QLineEdit::textChanged, this, &MainWindow::onFilterTyped);
    bar->addWidget(m_filterEdit);

    QPushButton* exportCbomBtn = new QPushButton("💾 Export CBOM / CSV…");
    exportCbomBtn->setObjectName("btnExportSecondary");
    connect(exportCbomBtn, &QPushButton::clicked, this, &MainWindow::onExportJsonClicked);
    bar->addWidget(exportCbomBtn);

    vl->addLayout(bar);

    // Codeforces High-Contrast Table
    m_tableView = new QTableView;
    m_tableView->setObjectName("cbomTable");
    m_tableView->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_tableView->setSelectionMode(QAbstractItemView::SingleSelection);
    m_tableView->setAlternatingRowColors(true);
    m_tableView->setShowGrid(true);
    m_tableView->verticalHeader()->setVisible(false);
    m_tableView->verticalHeader()->setDefaultSectionSize(34);
    m_tableView->horizontalHeader()->setStretchLastSection(false);
    m_tableView->horizontalHeader()->setHighlightSections(false);
    m_tableView->horizontalHeader()->setDefaultAlignment(Qt::AlignLeft | Qt::AlignVCenter);
    m_tableView->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
    m_tableView->horizontalHeader()->setSectionResizeMode(CbomTableModel::COL_PQC_REPLACEMENT, QHeaderView::Stretch);
    m_tableView->horizontalHeader()->setSectionResizeMode(CbomTableModel::COL_FILE_LINE, QHeaderView::Stretch);
    m_tableView->setEditTriggers(QAbstractItemView::NoEditTriggers);

    connect(m_tableView, &QTableView::clicked, this, &MainWindow::onTableRowClicked);
    connect(m_tableView, &QTableView::doubleClicked, this, [this](const QModelIndex& idx){
        onTableRowClicked(idx);
        onTabButtonClicked(2); // Jump to Inspector
    });

    // Right-click on table row opens code editor menu
    m_tableView->setContextMenuPolicy(Qt::CustomContextMenu);
    connect(m_tableView, &QTableView::customContextMenuRequested, this, [this](const QPoint& pos){
        QModelIndex idx = m_tableView->indexAt(pos);
        if (idx.isValid()) {
            onTableRowClicked(idx);
            onOpenFileMenuRequested(m_tableView->viewport()->mapToGlobal(pos));
        }
    });

    vl->addWidget(m_tableView, 1);
    return page;
}

// ─────────────────────────────────────────────────────────────
//  DETAIL TAB: Deep Asset Inspector
// ─────────────────────────────────────────────────────────────
QWidget* MainWindow::buildDetailTab() {
    QWidget* page = new QWidget;
    page->setObjectName("detailPage");
    QVBoxLayout* vl = new QVBoxLayout(page);
    vl->setContentsMargins(16, 12, 16, 12);
    vl->setSpacing(10);

    QLabel* pgTitle = new QLabel("Deep Cryptographic Asset Inspector");
    pgTitle->setObjectName("cardHeader");
    vl->addWidget(pgTitle);

    QWidget* inspCard = new QWidget;
    inspCard->setObjectName("slateCard");
    QGridLayout* gl = new QGridLayout(inspCard);
    gl->setContentsMargins(16, 16, 16, 16);
    gl->setHorizontalSpacing(16);
    gl->setVerticalSpacing(10);

    auto makeField = [&](int row, int col, const QString& title, QLabel*& outVal) {
        QVBoxLayout* fl = new QVBoxLayout;
        fl->setSpacing(2);
        QLabel* tl = new QLabel(title);
        tl->setStyleSheet("font-size:10px;font-weight:700;color:#64748B;background:transparent;");
        outVal = new QLabel("—");
        outVal->setStyleSheet("font-size:12px;font-weight:600;color:#0F172A;background:transparent;");
        fl->addWidget(tl);
        fl->addWidget(outVal);
        gl->addLayout(fl, row, col);
    };

    makeField(0, 0, "Algorithm Name & Key Size", m_detAlgo);
    makeField(0, 1, "Quantum Threat Assessment",   m_detRisk);
    makeField(1, 0, "Cipher Operating Mode",       m_detMode);
    makeField(1, 1, "Discovery Stage & Method",    m_detStage);
    makeField(0, 2, "Detection Confidence",        m_detConfidence);

    // Source File Location with Interactive Editor Button & Context Menu
    QVBoxLayout* flFile = new QVBoxLayout;
    flFile->setSpacing(3);
    QLabel* tlFile = new QLabel("Source File Location");
    tlFile->setStyleSheet("font-size:10px;font-weight:700;color:#64748B;background:transparent;");
    flFile->addWidget(tlFile);

    QHBoxLayout* fileRow = new QHBoxLayout;
    fileRow->setSpacing(8);

    m_detFile = new QLabel("—");
    m_detFile->setStyleSheet("font-size:12px;font-weight:600;color:#0F172A;background:transparent;");
    m_detFile->setContextMenuPolicy(Qt::CustomContextMenu);
    m_detFile->setCursor(Qt::PointingHandCursor);
    m_detFile->setToolTip("Click or Right-Click to open file in Code Editor (VS Code, Cursor, Xcode, etc.)");
    fileRow->addWidget(m_detFile, 1);

    m_btnOpenFile = new QPushButton(" ⚡ Open with Editor ▾ ");
    m_btnOpenFile->setObjectName("btnBrowseFile");
    m_btnOpenFile->setFixedHeight(26);
    m_btnOpenFile->setToolTip("Open source file in Visual Studio Code, Cursor, Xcode, Zed, or Default Editor");
    connect(m_btnOpenFile, &QPushButton::clicked, this, [this]{
        if (m_btnOpenFile) {
            onOpenFileMenuRequested(m_btnOpenFile->mapToGlobal(QPoint(0, m_btnOpenFile->height())));
        }
    });
    fileRow->addWidget(m_btnOpenFile);

    connect(m_detFile, &QLabel::customContextMenuRequested, this, [this](const QPoint& p){
        if (m_detFile) {
            onOpenFileMenuRequested(m_detFile->mapToGlobal(p));
        }
    });

    flFile->addLayout(fileRow);
    gl->addLayout(flFile, 2, 0);

    makeField(2, 1, "Source Line Number",          m_detLine);

    // NIST PQC Fix Recommendation
    QVBoxLayout* fixLayout = new QVBoxLayout;
    fixLayout->setSpacing(2);
    QLabel* fixTitle = new QLabel("NIST PQC Migration Path (FIPS 203/204/205)");
    fixTitle->setStyleSheet("font-size:10px;font-weight:700;color:#3182CE;background:transparent;");
    m_detFix = new QLabel("Select an asset from CBOM Inventory to view recommended PQC replacement.");
    m_detFix->setStyleSheet("font-size:12px;font-weight:700;color:#10B981;background:transparent;");
    m_detFix->setWordWrap(true);
    fixLayout->addWidget(fixTitle);
    fixLayout->addWidget(m_detFix);
    gl->addLayout(fixLayout, 3, 0, 1, 2);

    vl->addWidget(inspCard);

    // Matched Code Evidence Box
    QWidget* snipCard = new QWidget;
    snipCard->setObjectName("slateCard");
    QVBoxLayout* sl = new QVBoxLayout(snipCard);
    sl->setContentsMargins(14, 12, 14, 12);
    sl->setSpacing(6);

    QLabel* snipTitle = new QLabel("Extracted AST Syntax Evidence / Code Snippet");
    snipTitle->setObjectName("cardHeader");
    sl->addWidget(snipTitle);

    m_detSnip = new QTextEdit;
    m_detSnip->setReadOnly(true);
    m_detSnip->setPlaceholderText("No cryptographic asset selected yet. Click any row in CBOM Inventory to inspect.");
    m_detSnip->setObjectName("snippetViewer");
    sl->addWidget(m_detSnip, 1);

    vl->addWidget(snipCard, 1);
    return page;
}

// ─────────────────────────────────────────────────────────────
//  HISTORY TAB: Historical Audit Records & Recall
// ─────────────────────────────────────────────────────────────
QWidget* MainWindow::buildHistoryTab() {
    QWidget* page = new QWidget;
    page->setObjectName("historyPage");
    QVBoxLayout* vl = new QVBoxLayout(page);
    vl->setContentsMargins(16, 12, 16, 12);
    vl->setSpacing(10);

    // Header Toolbar
    QHBoxLayout* bar = new QHBoxLayout;
    bar->setSpacing(10);

    QLabel* title = new QLabel("Historical Cryptographic Audits");
    title->setObjectName("cardHeader");
    bar->addWidget(title);

    m_historyStatsLabel = new QLabel("0 past scans recorded");
    m_historyStatsLabel->setStyleSheet("font-size:11px;color:#64748B;font-weight:600;background:transparent;");
    bar->addWidget(m_historyStatsLabel);

    bar->addStretch();

    m_historyFilterEdit = new QLineEdit;
    m_historyFilterEdit->setPlaceholderText("🔍 Filter history records...");
    m_historyFilterEdit->setObjectName("filterEdit");
    m_historyFilterEdit->setFixedWidth(240);
    connect(m_historyFilterEdit, &QLineEdit::textChanged, this, &MainWindow::onHistoryFilterTyped);
    bar->addWidget(m_historyFilterEdit);

    m_btnClearHistoryBtn = new QPushButton("🗑 Clear History");
    m_btnClearHistoryBtn->setObjectName("btnStopScan");
    connect(m_btnClearHistoryBtn, &QPushButton::clicked, this, &MainWindow::onClearHistoryClicked);
    bar->addWidget(m_btnClearHistoryBtn);

    vl->addLayout(bar);

    // History Table
    m_historyTable = new QTableWidget;
    m_historyTable->setObjectName("cbomTable");
    m_historyTable->setColumnCount(9);
    m_historyTable->setHorizontalHeaderLabels({
        "#", "Date & Time", "Project Tag", "Target Repository",
        "Total Assets", "Critical", "Moderate", "Safe", "Actions"
    });
    m_historyTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_historyTable->setSelectionMode(QAbstractItemView::SingleSelection);
    m_historyTable->setAlternatingRowColors(true);
    m_historyTable->setShowGrid(true);
    m_historyTable->verticalHeader()->setVisible(false);
    m_historyTable->verticalHeader()->setDefaultSectionSize(36);
    m_historyTable->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    m_historyTable->horizontalHeader()->setSectionResizeMode(1, QHeaderView::ResizeToContents);
    m_historyTable->horizontalHeader()->setSectionResizeMode(2, QHeaderView::ResizeToContents);
    m_historyTable->horizontalHeader()->setSectionResizeMode(3, QHeaderView::Stretch);
    m_historyTable->horizontalHeader()->setSectionResizeMode(4, QHeaderView::ResizeToContents);
    m_historyTable->horizontalHeader()->setSectionResizeMode(5, QHeaderView::ResizeToContents);
    m_historyTable->horizontalHeader()->setSectionResizeMode(6, QHeaderView::ResizeToContents);
    m_historyTable->horizontalHeader()->setSectionResizeMode(7, QHeaderView::ResizeToContents);
    m_historyTable->horizontalHeader()->setSectionResizeMode(8, QHeaderView::ResizeToContents);
    m_historyTable->setEditTriggers(QAbstractItemView::NoEditTriggers);

    vl->addWidget(m_historyTable, 1);
    return page;
}

// ─────────────────────────────────────────────────────────────
//  BOTTOM BAR: Execution Log Dock
// ─────────────────────────────────────────────────────────────
QWidget* MainWindow::buildBottomBar() {
    m_logContainer = new QWidget;
    m_logContainer->setObjectName("logDock");
    QVBoxLayout* vl = new QVBoxLayout(m_logContainer);
    vl->setContentsMargins(16, 6, 16, 8);
    vl->setSpacing(6);

    QHBoxLayout* topRow = new QHBoxLayout;
    topRow->setSpacing(8);

    m_progressBar = new QProgressBar;
    m_progressBar->setObjectName("scanProgress");
    m_progressBar->setRange(0, 100);
    m_progressBar->setValue(0);
    m_progressBar->setFixedHeight(6);
    m_progressBar->setTextVisible(false);
    topRow->addWidget(m_progressBar, 1);

    m_logToggleBtn = new QPushButton("Console Log ▲");
    m_logToggleBtn->setObjectName("btnLogToggle");
    m_logToggleBtn->setCheckable(true);
    m_logToggleBtn->setChecked(true);
    connect(m_logToggleBtn, &QPushButton::clicked, this, [this](bool checked){
        m_logEdit->setVisible(checked);
        m_logToggleBtn->setText(checked ? "Console Log ▲" : "Console Log ▼");
    });
    topRow->addWidget(m_logToggleBtn);
    vl->addLayout(topRow);

    m_logEdit = new QTextEdit;
    m_logEdit->setObjectName("terminalLog");
    m_logEdit->setReadOnly(true);
    m_logEdit->setFixedHeight(85);
    vl->addWidget(m_logEdit);

    return m_logContainer;
}

// ─────────────────────────────────────────────────────────────
//  NAVIGATION TAB CONTROLLER
// ─────────────────────────────────────────────────────────────
void MainWindow::onTabButtonClicked(int index) {
    m_stackedPages->setCurrentIndex(index);
    m_btnNavDash->setChecked(index == 0);
    m_btnNavCbom->setChecked(index == 1);
    m_btnNavDetail->setChecked(index == 2);
    m_btnNavHistory->setChecked(index == 3);
}

// ─────────────────────────────────────────────────────────────
//  BROWSE BUTTON HANDLERS (DontUseNativeDialog for macOS)
// ─────────────────────────────────────────────────────────────
void MainWindow::onBrowseClicked() {
    onBrowseFolderClicked();
}

void MainWindow::onBrowseFolderClicked() {
    QString dir = QFileDialog::getExistingDirectory(
        this,
        "Select Repository or Directory to Audit",
        m_targetEdit->text().isEmpty() ? QDir::homePath() : m_targetEdit->text(),
        QFileDialog::ShowDirsOnly | QFileDialog::DontResolveSymlinks | QFileDialog::DontUseNativeDialog
    );
    if (!dir.isEmpty()) {
        m_targetEdit->setText(dir);
        log("📁 Selected audit folder: " + dir, "#3182CE");
    }
}

void MainWindow::onBrowseFileClicked() {
    QString file = QFileDialog::getOpenFileName(
        this,
        "Select Source or Binary File to Audit",
        m_targetEdit->text().isEmpty() ? QDir::homePath() : m_targetEdit->text(),
        "Source & Binary Files (*.cpp *.c *.h *.hpp *.cc *.py *.java *.go *.exe *.dll *.so *.bin *.pem *.crt *.conf);;All Files (*.*)",
        nullptr,
        QFileDialog::DontUseNativeDialog
    );
    if (!file.isEmpty()) {
        m_targetEdit->setText(file);
        log("📄 Selected single audit file: " + file, "#3182CE");
    }
}

// ─────────────────────────────────────────────────────────────
//  SCAN WORKER CONTROLLER
// ─────────────────────────────────────────────────────────────
void MainWindow::onStartScanClicked() {
    QString path = m_targetEdit->text().trimmed();
    if (path.isEmpty()) {
        QMessageBox::warning(this, "Target Required", "Please choose a file or folder to scan first.");
        return;
    }

    m_startBtn->setEnabled(false);
    m_stopBtn->setEnabled(true);
    m_progressBar->setValue(0);
    m_findings.clear();
    m_tableModel->clear();
    m_critCount = m_modCount = m_safeCount = 0;
    m_lastFilesScanned = 0;
    updateStatCards();

    for (int i = 0; i < 5; ++i) {
        m_algoBars[i]->setValue(0);
        m_algoCounts[i]->setText("0");
    }

    m_headerStatus->setText("● Scanning…");
    m_headerStatus->setObjectName("statusScanning");
    m_headerStatus->style()->unpolish(m_headerStatus);
    m_headerStatus->style()->polish(m_headerStatus);

    log("🚀 AST Cryptographic Engine initialized for: " + path, "#3182CE");

    if (m_worker && m_worker->isRunning()) {
        m_worker->requestStop();
        m_worker->wait(200);
        if (m_worker->isRunning()) {
            m_worker->terminate();
            m_worker->wait(100);
        }
    }

    m_worker->configure(
        path,
        m_cbSource->isChecked(),
        m_cbBinary->isChecked(),
        m_cbCert->isChecked(),
        m_projectEdit->text()
    );
    m_worker->start();
}

void MainWindow::onStopScanClicked() {
    if (m_worker && m_worker->isRunning()) {
        m_worker->requestStop();
        m_worker->wait(300);
        if (m_worker->isRunning()) {
            m_worker->terminate();
        }
        m_startBtn->setEnabled(true);
        m_stopBtn->setEnabled(false);
        m_headerStatus->setText("⏹ Stopped");
        m_headerStatus->setObjectName("statusComplete");
        m_headerStatus->style()->unpolish(m_headerStatus);
        m_headerStatus->style()->polish(m_headerStatus);
        log("⏹ Scan cancelled by user.", "#F59E0B");
    }
}

void MainWindow::onProgress(int current, int total, const QString& file) {
    m_lastFilesScanned = current;
    int pct = total > 0 ? (current * 100) / total : 0;
    m_progressBar->setValue(pct);
}

void MainWindow::onFindingDiscovered(ecdat::CryptoFinding finding) {
    m_findings.push_back(finding);
    m_tableModel->addFinding(finding);

    if (finding.riskLevel == ecdat::RiskLevel::CRITICAL) m_critCount++;
    else if (finding.riskLevel == ecdat::RiskLevel::MODERATE) m_modCount++;
    else m_safeCount++;

    updateStatCards();

    // Update Algorithm Breakdown Bars
    std::string a = finding.algorithmName;
    if (a.find("RSA") != std::string::npos || a.find("ECC") != std::string::npos || a.find("DH") != std::string::npos) {
        int v = m_algoBars[0]->value() + 1; m_algoBars[0]->setValue(v); m_algoCounts[0]->setText(QString::number(v));
    } else if (a.find("DES") != std::string::npos || a.find("3DES") != std::string::npos || a.find("RC4") != std::string::npos) {
        int v = m_algoBars[1]->value() + 1; m_algoBars[1]->setValue(v); m_algoCounts[1]->setText(QString::number(v));
    } else if (a.find("MD5") != std::string::npos || a.find("SHA-1") != std::string::npos || a.find("SHA1") != std::string::npos) {
        int v = m_algoBars[2]->value() + 1; m_algoBars[2]->setValue(v); m_algoCounts[2]->setText(QString::number(v));
    } else if (a.find("AES-128") != std::string::npos || a == "AES") {
        int v = m_algoBars[3]->value() + 1; m_algoBars[3]->setValue(v); m_algoCounts[3]->setText(QString::number(v));
    } else {
        int v = m_algoBars[4]->value() + 1; m_algoBars[4]->setValue(v); m_algoCounts[4]->setText(QString::number(v));
    }

    // Terminal Logging
    QString tag = finding.riskLevel == ecdat::RiskLevel::CRITICAL ? "[CRITICAL]"
                : finding.riskLevel == ecdat::RiskLevel::MODERATE ? "[MODERATE]" : "[SAFE]";
    QString col = finding.riskLevel == ecdat::RiskLevel::CRITICAL ? "#EF4444"
                : finding.riskLevel == ecdat::RiskLevel::MODERATE ? "#F59E0B" : "#10B981";

    QFileInfo fi(QString::fromStdString(finding.filePath));
    log(QString("%1 [%2 | %3] Discovered %4 in %5:%6 ➜ PQC Advisory: %7")
        .arg(tag)
        .arg(QString::fromStdString(finding.scannerSource))
        .arg(QString::fromStdString(finding.confidence))
        .arg(QString::fromStdString(finding.algorithmName))
        .arg(fi.fileName())
        .arg(finding.lineNumber)
        .arg(QString::fromStdString(finding.pqcReplacement)), col);
}

void MainWindow::onScanCompleted(ecdat::FindingList allFindings) {
    m_startBtn->setEnabled(true);
    m_stopBtn->setEnabled(false);
    m_progressBar->setValue(100);

    m_findings = allFindings;
    m_tableModel->setFindings(allFindings);

    m_critCount = m_modCount = m_safeCount = 0;
    for (const auto& f : m_findings) {
        if (f.riskLevel == ecdat::RiskLevel::CRITICAL) m_critCount++;
        else if (f.riskLevel == ecdat::RiskLevel::MODERATE) m_modCount++;
        else m_safeCount++;
    }

    updateStatCards();
    updateMoscaDashboard();

    // Compute Mosca for historical save
    ecdat::MoscaInput input;
    input.dataSecrecyLifetime = m_sliderX ? m_sliderX->value() : 15;
    input.migrationTime       = m_sliderY ? m_sliderY->value() : 3;
    input.quantumArrivalTime  = m_sliderZ ? m_sliderZ->value() : 10;
    ecdat::MoscaResult moscaResult = m_moscaEngine.calculate(input);

    // Automatically record to persistent history
    addScanToHistory(m_projectEdit->text(), m_targetEdit->text(), m_findings, m_lastFilesScanned, moscaResult);

    if (m_findings.empty()) {
        log("✅ Scan Finished: 0 cryptographic assets discovered in target path.", "#10B981");
    } else {
        log(QString("✅ Cryptographic Audit Complete! Cataloged %1 Assets (%2 Critical, %3 Moderate, %4 Quantum-Safe)")
            .arg(m_findings.size()).arg(m_critCount).arg(m_modCount).arg(m_safeCount), "#10B981");
    }

    if (m_tableView) {
        m_tableView->resizeColumnsToContents();
        m_tableView->horizontalHeader()->setSectionResizeMode(CbomTableModel::COL_PQC_REPLACEMENT, QHeaderView::Stretch);
        m_tableView->horizontalHeader()->setSectionResizeMode(CbomTableModel::COL_FILE_LINE, QHeaderView::Stretch);
    }

    m_headerStatus->setText("✓ Complete");
    m_headerStatus->setObjectName("statusComplete");
    m_headerStatus->style()->unpolish(m_headerStatus);
    m_headerStatus->style()->polish(m_headerStatus);

    onTabButtonClicked(1); // Switch to CBOM Grid
}

void MainWindow::onScanError(const QString& message) {
    m_startBtn->setEnabled(true);
    m_stopBtn->setEnabled(false);
    log("❌ Error: " + message, "#EF4444");
    QMessageBox::critical(this, "Audit Error", message);
}

// ─────────────────────────────────────────────────────────────
//  MOSCA'S THEOREM REAL-TIME RE-EVALUATION
// ─────────────────────────────────────────────────────────────
void MainWindow::onMoscaChanged() {
    updateMoscaDashboard();
}

void MainWindow::updateMoscaDashboard() {
    if (!m_gauge || !m_sliderX) return;

    ecdat::MoscaInput input;
    input.dataSecrecyLifetime = m_sliderX->value();
    input.migrationTime       = m_sliderY->value();
    input.quantumArrivalTime  = m_sliderZ->value();

    ecdat::MoscaResult result = m_moscaEngine.calculate(input);

    m_gauge->setRiskScore(result.riskScore);
    m_gauge->setStatus(result.status);

    double xy = input.dataSecrecyLifetime + input.migrationTime;
    double z  = input.quantumArrivalTime;
    double margin = z - xy;

    if (m_moscaFormulaLabel) {
        m_moscaFormulaLabel->setText(
            QString("X (%1 yrs) + Y (%2 yrs) = %3 yrs  vs  Z (%4 yrs)")
            .arg(input.dataSecrecyLifetime)
            .arg(input.migrationTime)
            .arg(xy)
            .arg(z)
        );
    }

    if (result.status == ecdat::MoscaStatus::RED_ALERT) {
        m_moscaBadge->setText("RED ALERT — IMMEDIATE PQC MIGRATION REQUIRED");
        m_moscaBadge->setObjectName("verdictCrit");
        m_moscaDesc->setText(QString("X + Y (%1 yrs) > Z (%2 yrs): Sensitive assets exceed quantum horizon. Harvest-Now-Decrypt-Later (HNDL) vulnerability active today.").arg(xy).arg(z));

        if (m_moscaMarginLabel) {
            m_moscaMarginLabel->setText(QString("🔴 Deficit: %1 yrs beyond CRQC horizon. Retroactive decryption threat active.").arg(std::abs(margin)));
            m_moscaMarginLabel->setStyleSheet("font-size:10px;font-weight:700;color:#EF4444;background:transparent;");
        }
    } else if (result.status == ecdat::MoscaStatus::AMBER_WARNING) {
        m_moscaBadge->setText("WARNING — PQC MIGRATION WINDOW EXPIRING");
        m_moscaBadge->setObjectName("verdictWarn");
        m_moscaDesc->setText(QString("X + Y (%1 yrs) approaching Z (%2 yrs): Only %3 yrs safety margin remaining. Migration roadmap needed.").arg(xy).arg(z).arg(margin));

        if (m_moscaMarginLabel) {
            m_moscaMarginLabel->setText(QString("🟡 Warning: Only %1 yrs margin remaining before quantum vulnerability.").arg(margin));
            m_moscaMarginLabel->setStyleSheet("font-size:10px;font-weight:700;color:#F59E0B;background:transparent;");
        }
    } else {
        m_moscaBadge->setText("SAFE — ADEQUATE QUANTUM TRANSITION WINDOW");
        m_moscaBadge->setObjectName("verdictSafe");
        m_moscaDesc->setText(QString("X + Y (%1 yrs) < Z (%2 yrs): Safe operational window (%3 yrs margin) available for scheduled transition.").arg(xy).arg(z).arg(margin));

        if (m_moscaMarginLabel) {
            m_moscaMarginLabel->setText(QString("🟢 Safe: +%1 yrs transition margin available.").arg(margin));
            m_moscaMarginLabel->setStyleSheet("font-size:10px;font-weight:700;color:#10B981;background:transparent;");
        }
    }

    m_moscaBadge->style()->unpolish(m_moscaBadge);
    m_moscaBadge->style()->polish(m_moscaBadge);
}

// ─────────────────────────────────────────────────────────────
//  INSPECTOR & FILTER SLOTS
// ─────────────────────────────────────────────────────────────
void MainWindow::onTableRowClicked(const QModelIndex& index) {
    if (!index.isValid()) return;
    const auto& f = m_tableModel->findingAt(index.row());

    m_detAlgo->setText(QString::fromStdString(f.algorithmName)
                       + (f.keyLength > 0 ? QString("  (%1 bits)").arg(f.keyLength) : ""));

    QString rText;
    if (f.riskLevel == ecdat::RiskLevel::CRITICAL) {
        rText = "🔴 CRITICAL (Broken by Shor's Algo)";
    } else if (f.riskLevel == ecdat::RiskLevel::MODERATE) {
        rText = "🟡 MODERATE (Weakened by Grover's Algo)";
    } else {
        rText = "🟢 SAFE (Quantum-Resistant)";
    }
    m_detRisk->setText(rText);

    QString a = QString::fromStdString(f.algorithmName).toUpper();
    QString mode = "N/A";
    if (a.contains("GCM")) mode = "GCM (Galois/Counter Mode)";
    else if (a.contains("CBC")) mode = "CBC (Cipher Block Chaining)";
    else if (a.contains("ECB")) mode = "ECB (Electronic Codebook - Insecure)";
    m_detMode->setText(mode);

    m_currentSelectedFile = QString::fromStdString(f.filePath);
    m_currentSelectedLine = f.lineNumber;

    m_detStage->setText(QString::fromStdString(f.scannerSource));
    if (m_detConfidence) {
        QString conf = f.confidence.empty() ? "100.0%" : QString::fromStdString(f.confidence);
        m_detConfidence->setText(conf + (conf.startsWith("100") ? " (Deterministic)" : " (ML Heuristic)"));
    }
    m_detFile->setText(QString::fromStdString(f.filePath));
    m_detLine->setText(f.lineNumber > 0 ? QString::number(f.lineNumber) : "Header / Global");
    m_detFix->setText(QString::fromStdString(f.pqcReplacement));
    m_detSnip->setText(QString::fromStdString(f.matchedSnippet));
}

void MainWindow::onFilterTyped(const QString& text) {
    m_tableModel->setFilter(text);
    if (m_tableStats) {
        m_tableStats->setText(QString("%1 assets displayed").arg(m_tableModel->rowCount()));
    }
}

// ─────────────────────────────────────────────────────────────
//  EXPORT CBOM / CSV / MARKDOWN (Universal Multi-Format Export)
// ─────────────────────────────────────────────────────────────
void MainWindow::onExportJsonClicked() {
    if (m_findings.empty()) {
        QMessageBox::information(this, "Inventory Empty",
            "There are currently no cryptographic findings to export.\n\n"
            "Please run an audit on a repository/file first, or load a previous scan from the Scan History tab.");
        return;
    }

    QString defaultName = "ecdat_cbom_" + QDateTime::currentDateTime().toString("yyyyMMdd_hhmmss");
    QString selectedFilter;
    QString path = QFileDialog::getSaveFileName(
        this,
        "Export Cryptographic Bill of Materials",
        defaultName + ".json",
        "CycloneDX CBOM JSON (*.json);;CSV Spreadsheet (*.csv);;Markdown Audit Report (*.md)",
        &selectedFilter,
        QFileDialog::DontUseNativeDialog
    );

    if (path.isEmpty()) return;

    QFileInfo fi(path);
    QString ext = fi.suffix().toLower();

    // ── Export CSV Format ─────────────────────────────────────
    if (ext == "csv" || selectedFilter.contains("CSV")) {
        if (!path.endsWith(".csv", Qt::CaseInsensitive)) path += ".csv";
        QFile file(path);
        if (file.open(QIODevice::WriteOnly | QIODevice::Text)) {
            QTextStream out(&file);
            out << "ID,Algorithm,Family,KeyLength,Mode,QuantumRisk,Confidence,CWE,PQC_Replacement,FilePath,LineNumber,Snippet,Scanner\n";
            for (const auto& f : m_findings) {
                QString risk = (f.riskLevel == ecdat::RiskLevel::CRITICAL) ? "CRITICAL"
                             : (f.riskLevel == ecdat::RiskLevel::MODERATE) ? "MODERATE" : "SAFE";
                auto clean = [](const std::string& s) {
                    QString qs = QString::fromStdString(s);
                    qs.replace("\"", "\"\"");
                    return "\"" + qs + "\"";
                };
                out << clean(f.id) << ","
                    << clean(f.algorithmName) << ","
                    << clean(f.algorithmFamily) << ","
                    << f.keyLength << ","
                    << clean(f.algorithmName) << ","
                    << risk << ","
                    << clean(f.confidence) << ","
                    << clean(f.cweId) << ","
                    << clean(f.pqcReplacement) << ","
                    << clean(f.filePath) << ","
                    << f.lineNumber << ","
                    << clean(f.matchedSnippet) << ","
                    << clean(f.scannerSource) << "\n";
            }
            log("💾 Successfully exported CSV Inventory to: " + path, "#10B981");
            QMessageBox::information(this, "Export Complete", "Cryptographic Inventory CSV successfully saved to:\n" + path);
            return;
        }
    }

    // ── Export Markdown Report Format ─────────────────────────
    if (ext == "md" || selectedFilter.contains("Markdown")) {
        if (!path.endsWith(".md", Qt::CaseInsensitive)) path += ".md";
        QFile file(path);
        if (file.open(QIODevice::WriteOnly | QIODevice::Text)) {
            QTextStream out(&file);
            out << "# Cryptographic Audit & PQC Assessment Report\n\n";
            out << "**Project:** " << (m_projectEdit->text().isEmpty() ? "Default" : m_projectEdit->text()) << "\n";
            out << "**Generated On:** " << QDateTime::currentDateTime().toString(Qt::ISODate) << "\n";
            out << "**Target Path:** `" << m_targetEdit->text() << "`\n\n";
            out << "## Executive Summary\n\n";
            out << "- **Total Discovered Assets:** " << m_findings.size() << "\n";
            out << "- **🔴 Critical Risk (Broken by Shor's):** " << m_critCount << "\n";
            out << "- **🟡 Moderate Risk (Weakened by Grover's):** " << m_modCount << "\n";
            out << "- **🟢 Quantum-Safe Assets:** " << m_safeCount << "\n\n";
            out << "## Mosca's Theorem Risk Assessment\n\n";
            out << "- **Data Secrecy Lifetime (X):** " << (m_sliderX ? m_sliderX->value() : 15) << " years\n";
            out << "- **PQC Migration Timeline (Y):** " << (m_sliderY ? m_sliderY->value() : 3) << " years\n";
            out << "- **CRQC Quantum Arrival (Z):** " << (m_sliderZ ? m_sliderZ->value() : 10) << " years\n";
            out << "- **Verdict:** " << (m_moscaBadge ? m_moscaBadge->text() : "N/A") << "\n\n";
            out << "## Cryptographic Asset Inventory (CBOM)\n\n";
            out << "| Algorithm | Type | Key Size | Risk Level | Confidence | Stage | PQC Recommended Migration | Location |\n";
            out << "|---|---|---|---|---|---|---|---|\n";
            for (const auto& f : m_findings) {
                QString risk = (f.riskLevel == ecdat::RiskLevel::CRITICAL) ? "🔴 CRITICAL"
                             : (f.riskLevel == ecdat::RiskLevel::MODERATE) ? "🟡 MODERATE" : "🟢 SAFE";
                QFileInfo fiLoc(QString::fromStdString(f.filePath));
                out << "| `" << QString::fromStdString(f.algorithmName) << "` "
                    << "| " << QString::fromStdString(f.algorithmFamily) << " "
                    << "| " << (f.keyLength > 0 ? QString::number(f.keyLength) + " bits" : "N/A") << " "
                    << "| " << risk << " "
                    << "| **" << QString::fromStdString(f.confidence) << "** "
                    << "| " << QString::fromStdString(f.scannerSource) << " "
                    << "| **" << QString::fromStdString(f.pqcReplacement) << "** "
                    << "| `" << fiLoc.fileName() << ":" << f.lineNumber << "` |\n";
            }
            log("💾 Successfully exported Markdown Audit Report to: " + path, "#10B981");
            QMessageBox::information(this, "Export Complete", "Markdown Audit Report successfully saved to:\n" + path);
            return;
        }
    }

    // ── Export CycloneDX v1.5 JSON (Default) ───────────────────
    if (!path.endsWith(".json", Qt::CaseInsensitive)) path += ".json";
    QJsonObject cbom;
    cbom["bomFormat"]   = "CycloneDX";
    cbom["specVersion"] = "1.5";
    cbom["version"]     = 1;
    cbom["timestamp"]   = QDateTime::currentDateTimeUtc().toString(Qt::ISODate);

    QJsonObject meta;
    meta["generator"] = "ECDAT v1.0 (NTRO / SIH 2026)";
    meta["project"]   = m_projectEdit->text().isEmpty() ? "Default" : m_projectEdit->text();
    meta["target"]    = m_targetEdit->text();
    cbom["metadata"]  = meta;

    QJsonArray components;
    for (const auto& f : m_findings) {
        QJsonObject comp;
        comp["bom-ref"]         = QString::fromStdString(f.id);
        comp["type"]            = "cryptographic-asset";
        comp["name"]            = QString::fromStdString(f.algorithmName);
        comp["algorithmFamily"] = QString::fromStdString(f.algorithmFamily);
        comp["keyLength"]       = f.keyLength;
        comp["filePath"]        = QString::fromStdString(f.filePath);
        comp["lineNumber"]      = f.lineNumber;
        comp["cweId"]           = QString::fromStdString(f.cweId);
        comp["confidence"]      = QString::fromStdString(f.confidence);
        comp["pqcReplacement"]  = QString::fromStdString(f.pqcReplacement);
        comp["matchedSnippet"]  = QString::fromStdString(f.matchedSnippet);
        comp["scanner"]         = QString::fromStdString(f.scannerSource);

        QString r;
        switch (f.riskLevel) {
            case ecdat::RiskLevel::CRITICAL: r = "CRITICAL"; break;
            case ecdat::RiskLevel::MODERATE: r = "MODERATE"; break;
            default:                         r = "SAFE"; break;
        }
        comp["quantumRisk"] = r;
        components.append(comp);
    }
    cbom["components"] = components;

    QJsonObject summary;
    summary["totalAssets"] = (int)m_findings.size();
    summary["critical"]    = m_critCount;
    summary["moderate"]    = m_modCount;
    summary["safe"]        = m_safeCount;
    summary["moscaX"]      = m_sliderX ? m_sliderX->value() : 15;
    summary["moscaY"]      = m_sliderY ? m_sliderY->value() : 3;
    summary["moscaZ"]      = m_sliderZ ? m_sliderZ->value() : 10;
    cbom["moscaSummary"]   = summary;

    QFile file(path);
    if (file.open(QIODevice::WriteOnly)) {
        file.write(QJsonDocument(cbom).toJson(QJsonDocument::Indented));
        log("💾 Successfully exported CycloneDX CBOM JSON to: " + path, "#10B981");
        QMessageBox::information(this, "CBOM Export Complete", "CycloneDX v1.5 Cryptographic Bill of Materials saved to:\n" + path);
    } else {
        QMessageBox::critical(this, "Export Error", "Could not write file: " + path);
    }
}

// ─────────────────────────────────────────────────────────────
//  SCAN HISTORY PERSISTENCE & MANAGEMENT
// ─────────────────────────────────────────────────────────────
static QString getHistoryFilePath() {
    QString dir = QDir::homePath() + "/.ecdat";
    QDir().mkpath(dir);
    return dir + "/scan_history.json";
}

void MainWindow::loadHistoryFromDisk() {
    m_historyRecords.clear();
    QFile f(getHistoryFilePath());
    if (!f.open(QIODevice::ReadOnly)) return;

    QJsonDocument doc = QJsonDocument::fromJson(f.readAll());
    if (!doc.isArray()) return;

    QJsonArray arr = doc.array();
    for (const auto& val : arr) {
        QJsonObject obj = val.toObject();
        ScanHistoryRecord rec;
        rec.id            = obj["id"].toString();
        rec.timestamp     = obj["timestamp"].toString();
        rec.projectName   = obj["project"].toString();
        rec.targetPath    = obj["target"].toString();
        rec.totalFiles    = obj["totalFiles"].toInt();
        rec.totalAssets   = obj["totalAssets"].toInt();
        rec.criticalCount = obj["critical"].toInt();
        rec.moderateCount = obj["moderate"].toInt();
        rec.safeCount     = obj["safe"].toInt();
        rec.riskScore     = obj["riskScore"].toDouble();
        rec.moscaVerdict  = obj["moscaVerdict"].toString();

        QJsonArray findingsArr = obj["findings"].toArray();
        for (const auto& fVal : findingsArr) {
            QJsonObject fo = fVal.toObject();
            ecdat::CryptoFinding cf;
            cf.id              = fo["id"].toString().toStdString();
            cf.filePath        = fo["filePath"].toString().toStdString();
            cf.lineNumber      = fo["lineNumber"].toInt();
            cf.algorithmName   = fo["algorithmName"].toString().toStdString();
            cf.algorithmFamily = fo["algorithmFamily"].toString().toStdString();
            cf.keyLength       = fo["keyLength"].toInt();
            cf.confidence      = fo.contains("confidence") ? fo["confidence"].toString().toStdString() : "100.0%";
            cf.cweId           = fo["cweId"].toString().toStdString();
            cf.pqcReplacement  = fo["pqcReplacement"].toString().toStdString();
            cf.matchedSnippet  = fo["matchedSnippet"].toString().toStdString();
            cf.scannerSource   = fo["scannerSource"].toString().toStdString();

            QString r = fo["riskLevel"].toString();
            if (r == "CRITICAL") cf.riskLevel = ecdat::RiskLevel::CRITICAL;
            else if (r == "MODERATE") cf.riskLevel = ecdat::RiskLevel::MODERATE;
            else cf.riskLevel = ecdat::RiskLevel::SAFE;

            rec.findings.push_back(cf);
        }
        m_historyRecords.push_back(rec);
    }
    refreshHistoryTable();
}

void MainWindow::saveHistoryToDisk() {
    QJsonArray arr;
    for (const auto& rec : m_historyRecords) {
        QJsonObject obj;
        obj["id"]           = rec.id;
        obj["timestamp"]    = rec.timestamp;
        obj["project"]      = rec.projectName;
        obj["target"]       = rec.targetPath;
        obj["totalFiles"]   = rec.totalFiles;
        obj["totalAssets"]  = rec.totalAssets;
        obj["critical"]     = rec.criticalCount;
        obj["moderate"]     = rec.moderateCount;
        obj["safe"]         = rec.safeCount;
        obj["riskScore"]    = rec.riskScore;
        obj["moscaVerdict"] = rec.moscaVerdict;

        QJsonArray findingsArr;
        for (const auto& f : rec.findings) {
            QJsonObject fo;
            fo["id"]              = QString::fromStdString(f.id);
            fo["filePath"]        = QString::fromStdString(f.filePath);
            fo["lineNumber"]      = f.lineNumber;
            fo["algorithmName"]   = QString::fromStdString(f.algorithmName);
            fo["algorithmFamily"] = QString::fromStdString(f.algorithmFamily);
            fo["keyLength"]       = f.keyLength;
            fo["confidence"]      = QString::fromStdString(f.confidence);
            fo["cweId"]           = QString::fromStdString(f.cweId);
            fo["pqcReplacement"]  = QString::fromStdString(f.pqcReplacement);
            fo["matchedSnippet"]  = QString::fromStdString(f.matchedSnippet);
            fo["scannerSource"]   = QString::fromStdString(f.scannerSource);
            fo["riskLevel"]       = (f.riskLevel == ecdat::RiskLevel::CRITICAL) ? "CRITICAL"
                                  : (f.riskLevel == ecdat::RiskLevel::MODERATE) ? "MODERATE" : "SAFE";
            findingsArr.append(fo);
        }
        obj["findings"] = findingsArr;
        arr.append(obj);
    }

    QFile f(getHistoryFilePath());
    if (f.open(QIODevice::WriteOnly)) {
        f.write(QJsonDocument(arr).toJson(QJsonDocument::Indented));
    }
}

void MainWindow::addScanToHistory(const QString& project, const QString& target, const ecdat::FindingList& findings, int filesScanned, const ecdat::MoscaResult& mosca) {
    ScanHistoryRecord rec;
    rec.id            = QString("SCAN-%1").arg(m_historyRecords.size() + 1, 3, 10, QChar('0'));
    rec.timestamp     = QDateTime::currentDateTime().toString("yyyy-MM-dd hh:mm:ss");
    rec.projectName   = project.isEmpty() ? "Default" : project;
    rec.targetPath    = target;
    rec.totalFiles    = filesScanned;
    rec.totalAssets   = static_cast<int>(findings.size());
    rec.criticalCount = m_critCount;
    rec.moderateCount = m_modCount;
    rec.safeCount     = m_safeCount;
    rec.riskScore     = mosca.riskScore;
    rec.moscaVerdict  = QString::fromStdString(mosca.statusMessage);
    rec.findings      = findings;

    m_historyRecords.prepend(rec); // Most recent first
    saveHistoryToDisk();
    refreshHistoryTable();
}

void MainWindow::refreshHistoryTable() {
    if (!m_historyTable) return;
    m_historyTable->setRowCount(0);

    QString filter = m_historyFilterEdit ? m_historyFilterEdit->text().toLower() : "";

    for (int i = 0; i < m_historyRecords.size(); ++i) {
        const auto& rec = m_historyRecords[i];

        if (!filter.isEmpty()) {
            QString hay = (rec.id + " " + rec.projectName + " " + rec.targetPath + " " + rec.timestamp).toLower();
            if (!hay.contains(filter)) continue;
        }

        int row = m_historyTable->rowCount();
        m_historyTable->insertRow(row);

        m_historyTable->setItem(row, 0, new QTableWidgetItem(rec.id));
        m_historyTable->setItem(row, 1, new QTableWidgetItem(rec.timestamp));
        m_historyTable->setItem(row, 2, new QTableWidgetItem(rec.projectName));

        QFileInfo fi(rec.targetPath);
        m_historyTable->setItem(row, 3, new QTableWidgetItem(fi.fileName().isEmpty() ? rec.targetPath : fi.fileName()));
        m_historyTable->item(row, 3)->setToolTip(rec.targetPath);

        m_historyTable->setItem(row, 4, new QTableWidgetItem(QString::number(rec.totalAssets)));

        // Critical item
        QTableWidgetItem* critItem = new QTableWidgetItem(QString::number(rec.criticalCount));
        critItem->setForeground(QBrush(QColor("#EF4444")));
        critItem->setFont(QFont("", -1, QFont::Bold));
        m_historyTable->setItem(row, 5, critItem);

        // Moderate item
        QTableWidgetItem* modItem = new QTableWidgetItem(QString::number(rec.moderateCount));
        modItem->setForeground(QBrush(QColor("#F59E0B")));
        modItem->setFont(QFont("", -1, QFont::Bold));
        m_historyTable->setItem(row, 6, modItem);

        // Safe item
        QTableWidgetItem* safeItem = new QTableWidgetItem(QString::number(rec.safeCount));
        safeItem->setForeground(QBrush(QColor("#10B981")));
        safeItem->setFont(QFont("", -1, QFont::Bold));
        m_historyTable->setItem(row, 7, safeItem);

        // Action Buttons Widget
        QWidget* actWidget = new QWidget;
        QHBoxLayout* al = new QHBoxLayout(actWidget);
        al->setContentsMargins(4, 2, 4, 2);
        al->setSpacing(4);

        QPushButton* btnLoad = new QPushButton("📥 Load");
        btnLoad->setObjectName("btnBrowseFile");
        btnLoad->setFixedHeight(24);
        connect(btnLoad, &QPushButton::clicked, this, [this, i]{ onLoadHistoryRecord(i); });
        al->addWidget(btnLoad);

        QPushButton* btnDel = new QPushButton("🗑");
        btnDel->setObjectName("btnStopScan");
        btnDel->setFixedHeight(24);
        btnDel->setFixedWidth(28);
        connect(btnDel, &QPushButton::clicked, this, [this, i]{ onDeleteHistoryRecord(i); });
        al->addWidget(btnDel);

        m_historyTable->setCellWidget(row, 8, actWidget);
    }

    if (m_historyStatsLabel) {
        m_historyStatsLabel->setText(QString("%1 past audits stored").arg(m_historyRecords.size()));
    }
}

void MainWindow::onLoadHistoryRecord(int index) {
    if (index < 0 || index >= m_historyRecords.size()) return;
    const auto& rec = m_historyRecords[index];

    m_projectEdit->setText(rec.projectName);
    m_targetEdit->setText(rec.targetPath);
    m_findings = rec.findings;
    m_tableModel->setFindings(m_findings);

    m_critCount = rec.criticalCount;
    m_modCount  = rec.moderateCount;
    m_safeCount = rec.safeCount;

    updateStatCards();
    updateMoscaDashboard();

    if (m_tableView) {
        m_tableView->resizeColumnsToContents();
        m_tableView->horizontalHeader()->setSectionResizeMode(CbomTableModel::COL_PQC_REPLACEMENT, QHeaderView::Stretch);
        m_tableView->horizontalHeader()->setSectionResizeMode(CbomTableModel::COL_FILE_LINE, QHeaderView::Stretch);
    }

    onTabButtonClicked(1); // Jump to CBOM Inventory
}

void MainWindow::onDeleteHistoryRecord(int index) {
    if (index < 0 || index >= m_historyRecords.size()) return;
    auto reply = QMessageBox::question(this, "Delete History Record",
        "Are you sure you want to delete this scan record from history?",
        QMessageBox::Yes | QMessageBox::No);
    if (reply == QMessageBox::Yes) {
        m_historyRecords.removeAt(index);
        saveHistoryToDisk();
        refreshHistoryTable();
        log("🗑 Deleted scan record from history.", "#64748B");
    }
}

void MainWindow::onClearHistoryClicked() {
    if (m_historyRecords.isEmpty()) return;
    auto reply = QMessageBox::question(this, "Clear All History",
        "Are you sure you want to permanently clear all historical scan records?",
        QMessageBox::Yes | QMessageBox::No);
    if (reply == QMessageBox::Yes) {
        m_historyRecords.clear();
        saveHistoryToDisk();
        refreshHistoryTable();
        log("🗑 All historical audit records cleared.", "#64748B");
    }
}

void MainWindow::onHistoryFilterTyped(const QString&) {
    refreshHistoryTable();
}

// ─────────────────────────────────────────────────────────────
//  LOGGING & UTILITIES
// ─────────────────────────────────────────────────────────────
void MainWindow::log(const QString& msg, const QString& color) {
    QString ts = QDateTime::currentDateTime().toString("hh:mm:ss");
    m_logEdit->append(
        QString("<span style='color:#94A3B8;'>[%1]</span> <span style='color:%2;'>%3</span>")
        .arg(ts, color, msg));
}

void MainWindow::updateStatCards() {
    auto n = [](int val) { return QString::number(val); };
    int total = m_critCount + m_modCount + m_safeCount;

    if (m_statCritCount)  m_statCritCount->setText(n(m_critCount));
    if (m_statModCount)   m_statModCount->setText(n(m_modCount));
    if (m_statSafeCount)  m_statSafeCount->setText(n(m_safeCount));
    if (m_statTotalCount) m_statTotalCount->setText(n(total));

    if (m_tableStats) {
        m_tableStats->setText(QString("%1 assets displayed").arg(m_tableModel ? m_tableModel->rowCount() : 0));
    }
}

QFrame* MainWindow::makeHLine() {
    QFrame* f = new QFrame;
    f->setFrameShape(QFrame::HLine);
    f->setFrameShadow(QFrame::Plain);
    f->setStyleSheet("color:#E2E8F0;background-color:#E2E8F0;border:none;max-height:1px;");
    return f;
}

// ─────────────────────────────────────────────────────────────
//  CODE EDITOR INTEGRATION & FILE REVEAL
// ─────────────────────────────────────────────────────────────
void MainWindow::onOpenFileMenuRequested(const QPoint& globalPos) {
    if (m_currentSelectedFile.isEmpty() || m_currentSelectedFile == "—") {
        QMessageBox::information(this, "No Asset Selected",
            "Please select a cryptographic asset from CBOM Inventory first to view its source file location.");
        return;
    }

    QMenu menu(this);
    menu.setStyleSheet(
        "QMenu { background-color: #FFFFFF; border: 1px solid #CBD5E1; border-radius: 6px; padding: 4px; }"
        "QMenu::item { padding: 6px 20px; font-size: 11px; font-weight: 600; color: #0F172A; border-radius: 3px; }"
        "QMenu::item:selected { background-color: #3182CE; color: #FFFFFF; }"
        "QMenu::separator { height: 1px; background: #E2E8F0; margin: 4px 6px; }"
    );

    QFileInfo fi(m_currentSelectedFile);
    QAction* hdr = menu.addAction(QString("📄 %1 (Line %2)").arg(fi.fileName()).arg(m_currentSelectedLine));
    hdr->setEnabled(false);
    QFont hf = hdr->font(); hf.setBold(true); hdr->setFont(hf);
    menu.addSeparator();

    // 1. Visual Studio Code
    QAction* actVscode = menu.addAction("💻 Visual Studio Code");
    connect(actVscode, &QAction::triggered, this, [this]{
        openFileInEditor("vscode", m_currentSelectedFile, m_currentSelectedLine);
    });

    // 2. Cursor
    QAction* actCursor = menu.addAction("✨ Cursor AI Editor");
    connect(actCursor, &QAction::triggered, this, [this]{
        openFileInEditor("cursor", m_currentSelectedFile, m_currentSelectedLine);
    });

    // 3. Xcode
    QAction* actXcode = menu.addAction("🛠 Xcode IDE");
    connect(actXcode, &QAction::triggered, this, [this]{
        openFileInEditor("xcode", m_currentSelectedFile, m_currentSelectedLine);
    });

    // 4. Zed
    QAction* actZed = menu.addAction("⚡ Zed Editor");
    connect(actZed, &QAction::triggered, this, [this]{
        openFileInEditor("zed", m_currentSelectedFile, m_currentSelectedLine);
    });

    // 5. IntelliJ IDEA / PyCharm
    QAction* actIdea = menu.addAction("☕ IntelliJ IDEA / PyCharm");
    connect(actIdea, &QAction::triggered, this, [this]{
        openFileInEditor("idea", m_currentSelectedFile, m_currentSelectedLine);
    });

    // 6. Sublime Text
    QAction* actSublime = menu.addAction("📝 Sublime Text");
    connect(actSublime, &QAction::triggered, this, [this]{
        openFileInEditor("sublime", m_currentSelectedFile, m_currentSelectedLine);
    });

    // 7. Default System Editor
    QAction* actDefault = menu.addAction("🌐 Default System Application");
    connect(actDefault, &QAction::triggered, this, [this]{
        openFileInEditor("default", m_currentSelectedFile, m_currentSelectedLine);
    });

    menu.addSeparator();

    // 8. Reveal in Finder
    QAction* actFinder = menu.addAction("📂 Reveal in Finder / File Manager");
    connect(actFinder, &QAction::triggered, this, [this]{
        revealInFileManager(m_currentSelectedFile);
    });

    // 9. Copy File Path
    QAction* actCopy = menu.addAction("📋 Copy File Path");
    connect(actCopy, &QAction::triggered, this, [this]{
        QApplication::clipboard()->setText(m_currentSelectedFile);
        log("📋 Copied path to clipboard: " + m_currentSelectedFile, "#3182CE");
    });

    // 10. Copy Path with Line
    QAction* actCopyLine = menu.addAction("📋 Copy Path with Line (file:line)");
    connect(actCopyLine, &QAction::triggered, this, [this]{
        QString ref = QString("%1:%2").arg(m_currentSelectedFile).arg(m_currentSelectedLine);
        QApplication::clipboard()->setText(ref);
        log("📋 Copied line reference to clipboard: " + ref, "#3182CE");
    });

    menu.exec(globalPos);
}

void MainWindow::openFileInEditor(const QString& editor, const QString& filePath, int lineNumber) {
    if (filePath.isEmpty()) return;

    QFileInfo fi(filePath);
    if (!fi.exists()) {
        QMessageBox::warning(this, "File Not Found", "The target file does not exist on disk:\n" + filePath);
        return;
    }

    log(QString("⚡ Launching %1 for %2 (line %3)...").arg(editor, fi.fileName()).arg(lineNumber), "#3182CE");

#if defined(Q_OS_MAC)
    if (editor == "vscode") {
        if (!QProcess::startDetached("code", {"-g", QString("%1:%2").arg(filePath).arg(lineNumber)})) {
            QProcess::startDetached("open", {"-a", "Visual Studio Code", filePath});
        }
    } else if (editor == "cursor") {
        if (!QProcess::startDetached("cursor", {"-g", QString("%1:%2").arg(filePath).arg(lineNumber)})) {
            QProcess::startDetached("open", {"-a", "Cursor", filePath});
        }
    } else if (editor == "zed") {
        if (!QProcess::startDetached("zed", {QString("%1:%2").arg(filePath).arg(lineNumber)})) {
            QProcess::startDetached("open", {"-a", "Zed", filePath});
        }
    } else if (editor == "xcode") {
        if (!QProcess::startDetached("xed", {"-line", QString::number(lineNumber), filePath})) {
            QProcess::startDetached("open", {"-a", "Xcode", filePath});
        }
    } else if (editor == "sublime") {
        if (!QProcess::startDetached("subl", {QString("%1:%2").arg(filePath).arg(lineNumber)})) {
            QProcess::startDetached("open", {"-a", "Sublime Text", filePath});
        }
    } else if (editor == "idea") {
        if (!QProcess::startDetached("idea", {"--line", QString::number(lineNumber), filePath}) &&
            !QProcess::startDetached("pycharm", {"--line", QString::number(lineNumber), filePath})) {
            if (!QProcess::startDetached("open", {"-a", "IntelliJ IDEA CE", filePath})) {
                QProcess::startDetached("open", {"-a", "PyCharm CE", filePath});
            }
        }
    } else {
        QDesktopServices::openUrl(QUrl::fromLocalFile(filePath));
    }
#elif defined(Q_OS_WIN)
    if (editor == "vscode") {
        QProcess::startDetached("code.cmd", {"-g", QString("%1:%2").arg(filePath).arg(lineNumber)});
    } else if (editor == "cursor") {
        QProcess::startDetached("cursor.cmd", {"-g", QString("%1:%2").arg(filePath).arg(lineNumber)});
    } else {
        QDesktopServices::openUrl(QUrl::fromLocalFile(filePath));
    }
#else
    if (editor == "vscode") {
        QProcess::startDetached("code", {"-g", QString("%1:%2").arg(filePath).arg(lineNumber)});
    } else if (editor == "cursor") {
        QProcess::startDetached("cursor", {"-g", QString("%1:%2").arg(filePath).arg(lineNumber)});
    } else {
        QDesktopServices::openUrl(QUrl::fromLocalFile(filePath));
    }
#endif
}

void MainWindow::revealInFileManager(const QString& filePath) {
    if (filePath.isEmpty()) return;

#if defined(Q_OS_MAC)
    QProcess::startDetached("open", {"-R", filePath});
#elif defined(Q_OS_WIN)
    QProcess::startDetached("explorer.exe", {"/select,", QDir::toNativeSeparators(filePath)});
#else
    QDesktopServices::openUrl(QUrl::fromLocalFile(QFileInfo(filePath).absolutePath()));
#endif
    log("📂 Revealed in Finder: " + filePath, "#3182CE");
}

