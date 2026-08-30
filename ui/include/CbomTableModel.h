#pragma once

#include <QAbstractTableModel>
#include <QColor>
#include "../../core/include/CryptoFinding.h"

class CbomTableModel : public QAbstractTableModel {
    Q_OBJECT

public:
    // Columns matching the spec table:
    // Algorithm | Type | Key Length | Quantum Risk | Confidence | Mosca Urgency | PQC Replacement | File & Line | Detection Stage
    enum Column {
        COL_ALGORITHM = 0,
        COL_TYPE,
        COL_KEY_LENGTH,
        COL_QUANTUM_RISK,
        COL_CONFIDENCE,
        COL_MOSCA_URGENCY,
        COL_PQC_REPLACEMENT,
        COL_FILE_LINE,
        COL_DETECTION_STAGE,
        COL_COUNT
    };

    explicit CbomTableModel(QObject* parent = nullptr);

    int rowCount(const QModelIndex& parent = {}) const override;
    int columnCount(const QModelIndex& parent = {}) const override;
    QVariant data(const QModelIndex& index, int role = Qt::DisplayRole) const override;
    QVariant headerData(int section, Qt::Orientation orientation,
                        int role = Qt::DisplayRole) const override;

    void addFinding(const ecdat::CryptoFinding& finding);
    void setFindings(const ecdat::FindingList& findings);
    void clear();
    void setFilter(const QString& text);
    const ecdat::CryptoFinding& findingAt(int row) const;

private:
    ecdat::FindingList m_allFindings;
    ecdat::FindingList m_filtered;
    QString            m_filterText;

    void rebuildFilter();
    QColor riskColor(ecdat::RiskLevel r) const;
    QString riskText(ecdat::RiskLevel r) const;
    QString modeFromAlgo(const std::string& algo) const;
    QString stageFromType(ecdat::FindingType t) const;
};
