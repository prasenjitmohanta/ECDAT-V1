#pragma once

#include <QMainWindow>
#include <QStackedWidget>
#include <QTableView>
#include <QTableWidget>
#include <QTextEdit>
#include <QProgressBar>
#include <QPushButton>
#include <QLineEdit>
#include <QLabel>
#include <QCheckBox>
#include <QSlider>
#include <QFrame>
#include <QScrollArea>
#include <QMap>
#include <QVector>
#include <QDateTime>

#include "ScanWorker.h"
#include "RiskGaugeWidget.h"
#include "CbomTableModel.h"
#include "../../core/include/MoscaEngine.h"
#include "../../core/include/CryptoFinding.h"

// ── Scan History Data Model ────────────────────────────────────
struct ScanHistoryRecord {
    QString id;
    QString timestamp;
    QString projectName;
    QString targetPath;
    int totalFiles = 0;
    int totalAssets = 0;
    int criticalCount = 0;
    int moderateCount = 0;
    int safeCount = 0;
    double riskScore = 0.0;
    QString moscaVerdict;
    ecdat::FindingList findings;
};

class MainWindow : public QMainWindow {
    Q_OBJECT

public:
    explicit MainWindow(QWidget* parent = nullptr);
    ~MainWindow() override;

private slots:
    void onBrowseClicked();
    void onBrowseFolderClicked();
    void onBrowseFileClicked();
    void onStartScanClicked();
    void onStopScanClicked();
    void onExportJsonClicked();
    void onProgress(int current, int total, const QString& file);
    void onFindingDiscovered(ecdat::CryptoFinding finding);
    void onScanCompleted(ecdat::FindingList allFindings);
    void onScanError(const QString& message);
    void onMoscaChanged();
    void onTableRowClicked(const QModelIndex& index);
    void onFilterTyped(const QString& text);
    void onTabButtonClicked(int index);
    void onThemeToggled();

    // ── Code Editor Open Slots ─────────────────────────────────
    void onOpenFileMenuRequested(const QPoint& globalPos);
    void openFileInEditor(const QString& editorCmd, const QString& filePath, int lineNumber);
    void revealInFileManager(const QString& filePath);

    // ── History Slots ──────────────────────────────────────────
    void onLoadHistoryRecord(int index);
    void onDeleteHistoryRecord(int index);
    void onClearHistoryClicked();
    void onHistoryFilterTyped(const QString& text);

private:
    void setupUi();
    void setupMenuBar();
    void applyTheme(bool isDark);

    QWidget* buildHeaderBar();
    QWidget* buildDashboardTab();
    QWidget* buildCbomTab();
    QWidget* buildDetailTab();
    QWidget* buildHistoryTab();
    QWidget* buildBottomBar();

    void log(const QString& msg, const QString& color = "#64748B");
    void updateStatCards();
    void updateMoscaDashboard();
    QFrame* makeHLine();

    // ── History Helpers ────────────────────────────────────────
    void loadHistoryFromDisk();
    void saveHistoryToDisk();
    void addScanToHistory(const QString& project, const QString& target, const ecdat::FindingList& findings, int filesScanned, const ecdat::MoscaResult& mosca);
    void refreshHistoryTable();

    // ── Header Navigation Buttons ─────────────────────────────
    QPushButton* m_btnNavDash    = nullptr;
    QPushButton* m_btnNavCbom    = nullptr;
    QPushButton* m_btnNavDetail  = nullptr;
    QPushButton* m_btnNavHistory = nullptr;
    QPushButton* m_btnThemeToggle= nullptr;

    QLabel* m_headerStatus = nullptr;
    QLabel* m_headerTarget = nullptr;

    // ── Scan Configuration Controls ───────────────────────────
    QLineEdit*   m_targetEdit     = nullptr;
    QPushButton* m_browseBtn      = nullptr;
    QPushButton* m_browseFileBtn  = nullptr;
    QCheckBox*   m_cbSource       = nullptr;
    QCheckBox*   m_cbBinary       = nullptr;
    QCheckBox*   m_cbCert         = nullptr;
    QLineEdit*   m_projectEdit    = nullptr;
    QPushButton* m_startBtn       = nullptr;
    QPushButton* m_stopBtn        = nullptr;

    // ── Mosca Interactive Sliders & Formula Labels ────────────
    QSlider* m_sliderX = nullptr;
    QSlider* m_sliderY = nullptr;
    QSlider* m_sliderZ = nullptr;
    QLabel*  m_labelX  = nullptr;
    QLabel*  m_labelY  = nullptr;
    QLabel*  m_labelZ  = nullptr;
    QLabel*  m_moscaFormulaLabel = nullptr;
    QLabel*  m_moscaMarginLabel  = nullptr;
    QLabel*  m_moscaActionLabel  = nullptr;

    // ── Hero Stat Cards ───────────────────────────────────────
    QLabel* m_statCritCount  = nullptr;
    QLabel* m_statModCount   = nullptr;
    QLabel* m_statSafeCount  = nullptr;
    QLabel* m_statTotalCount = nullptr;

    // ── Gauge & Mosca Assessment ──────────────────────────────
    RiskGaugeWidget* m_gauge         = nullptr;
    QLabel*          m_moscaBadge    = nullptr;
    QLabel*          m_moscaDesc     = nullptr;

    // ── Algorithm Breakdown Bars ──────────────────────────────
    QProgressBar* m_algoBars[5]   = {};
    QLabel*       m_algoCounts[5] = {};

    // ── CBOM Table Tab ────────────────────────────────────────
    QLineEdit*      m_filterEdit  = nullptr;
    QTableView*     m_tableView   = nullptr;
    CbomTableModel* m_tableModel  = nullptr;
    QLabel*         m_tableStats  = nullptr;

    // ── Deep Inspector Tab ────────────────────────────────────
    QLabel*      m_detAlgo       = nullptr;
    QLabel*      m_detRisk       = nullptr;
    QLabel*      m_detMode       = nullptr;
    QLabel*      m_detStage      = nullptr;
    QLabel*      m_detConfidence = nullptr;
    QLabel*      m_detFile       = nullptr;
    QLabel*      m_detLine       = nullptr;
    QLabel*      m_detFix        = nullptr;
    QTextEdit*   m_detSnip       = nullptr;
    QPushButton* m_btnOpenFile   = nullptr;
    QString      m_currentSelectedFile;
    int          m_currentSelectedLine = 0;

    // ── History Tab ───────────────────────────────────────────
    QTableWidget* m_historyTable       = nullptr;
    QLineEdit*    m_historyFilterEdit  = nullptr;
    QLabel*       m_historyStatsLabel  = nullptr;
    QPushButton*  m_btnClearHistoryBtn = nullptr;

    // ── Bottom Dock ───────────────────────────────────────────
    QTextEdit*    m_logEdit      = nullptr;
    QProgressBar* m_progressBar  = nullptr;
    QPushButton*  m_exportBtn    = nullptr;
    QPushButton*  m_logToggleBtn = nullptr;
    QWidget*      m_logContainer = nullptr;

    // Stacked Pages
    QStackedWidget* m_stackedPages = nullptr;

    // ── Backend Engine & Data ─────────────────────────────────
    ScanWorker*              m_worker = nullptr;
    ecdat::FindingList       m_findings;
    ecdat::MoscaEngine       m_moscaEngine;
    QVector<ScanHistoryRecord> m_historyRecords;
    int  m_critCount = 0, m_modCount = 0, m_safeCount = 0;
    int  m_lastFilesScanned = 0;
    bool m_isDarkMode = false;
};
