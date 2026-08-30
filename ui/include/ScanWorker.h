#pragma once

// ============================================================
//  ScanWorker.h
//  ECDAT Background Scanner Thread
//  Directly interfaces with AST-Parser-Backend / AstScanner
// ============================================================
//made by - Tourist

#include <QThread>
#include <QString>
#include "../../core/include/CryptoFinding.h"

class ScanWorker : public QThread {
    Q_OBJECT

public:
    explicit ScanWorker(QObject* parent = nullptr);

    // Called by MainWindow before starting the thread
    void configure(const QString& targetPath,
                   bool scanSource,
                   bool scanBinary,
                   bool scanCert,
                   const QString& projectName);

    // Call this to request graceful cancellation
    void requestStop() { m_stopRequested = true; }

signals:
    // Emitted as each file is scanned (current, total, filename)
    void progressUpdate(int current, int total, const QString& currentFile);

    // Emitted immediately when a new finding is discovered
    void findingDiscovered(ecdat::CryptoFinding finding);

    // Emitted once when the entire scan is done
    void scanCompleted(ecdat::FindingList allFindings);

    // Emitted if something goes wrong
    void errorOccurred(const QString& message);

protected:
    // Qt calls this when start() is invoked — runs in background thread
    void run() override;

private:
    QString m_targetPath;
    bool    m_scanSource  = true;
    bool    m_scanBinary  = true;
    bool    m_scanCert    = true;
    QString m_projectName;
    bool    m_stopRequested = false;
};
