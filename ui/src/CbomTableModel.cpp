#include "../include/CbomTableModel.h"
#include <QBrush>
#include <QFont>
#include <filesystem>

CbomTableModel::CbomTableModel(QObject* parent) : QAbstractTableModel(parent) {}

int CbomTableModel::rowCount(const QModelIndex&) const { return static_cast<int>(m_filtered.size()); }
int CbomTableModel::columnCount(const QModelIndex&) const { return COL_COUNT; }

QVariant CbomTableModel::data(const QModelIndex& index, int role) const {
    if (!index.isValid() || index.row() >= (int)m_filtered.size()) return {};
    const auto& f = m_filtered[index.row()];

    if (role == Qt::DisplayRole) {
        switch (index.column()) {
        case COL_ALGORITHM:
            return QString::fromStdString(f.algorithmName);
        case COL_TYPE:
            return QString::fromStdString(f.algorithmFamily);
        case COL_KEY_LENGTH:
            return f.keyLength > 0 ? QString::number(f.keyLength) + " bits" : "N/A";
        case COL_QUANTUM_RISK:
            return riskText(f.riskLevel);
        case COL_CONFIDENCE:
            return f.confidence.empty() ? "100.0%" : QString::fromStdString(f.confidence);
        case COL_MOSCA_URGENCY:
            return QString::fromStdString(f.fixDeadline.empty() ? f.fixUrgency : f.fixDeadline);
        case COL_PQC_REPLACEMENT:
            return QString::fromStdString(f.pqcReplacement);
        case COL_FILE_LINE: {
            std::filesystem::path p(f.filePath);
            QString s = QString::fromStdString(p.filename().string());
            if (f.lineNumber > 0) s += ":" + QString::number(f.lineNumber);
            return s;
        }
        case COL_DETECTION_STAGE:
            if (!f.scannerSource.empty()) return QString::fromStdString(f.scannerSource);
            return stageFromType(f.type);
        default: return {};
        }
    }

    if (role == Qt::BackgroundRole) {
        QColor bg = riskColor(f.riskLevel);
        bg.setAlpha(18);
        return QBrush(bg);
    }

    if (role == Qt::ForegroundRole) {
        if (index.column() == COL_QUANTUM_RISK)
            return QBrush(riskColor(f.riskLevel));
        if (index.column() == COL_CONFIDENCE) {
            QString c = QString::fromStdString(f.confidence);
            if (c.startsWith("100") || c.contains("HIGH")) return QBrush(QColor("#10B981"));
            return QBrush(QColor("#F59E0B"));
        }
        if (index.column() == COL_MOSCA_URGENCY) {
            if (f.riskLevel == ecdat::RiskLevel::CRITICAL) return QBrush(QColor("#EF4444"));
            if (f.riskLevel == ecdat::RiskLevel::MODERATE) return QBrush(QColor("#F59E0B"));
            return QBrush(QColor("#10B981"));
        }
        if (index.column() == COL_PQC_REPLACEMENT)
            return QBrush(QColor("#0284C7"));
    }

    if (role == Qt::FontRole && (index.column() == COL_QUANTUM_RISK || index.column() == COL_CONFIDENCE || index.column() == COL_MOSCA_URGENCY)) {
        QFont font; font.setBold(true); return font;
    }

    if (role == Qt::ToolTipRole) {
        return QString("File: %1\nLine: %2\nStage: %3 (Confidence: %4)\nSnippet/Evidence: %5\nPQC Fix: %6\nMosca: X=%7y, Y=%8y (%9)")
            .arg(QString::fromStdString(f.filePath))
            .arg(f.lineNumber)
            .arg(QString::fromStdString(f.scannerSource))
            .arg(QString::fromStdString(f.confidence))
            .arg(QString::fromStdString(f.matchedSnippet))
            .arg(QString::fromStdString(f.pqcReplacement))
            .arg(f.moscaX)
            .arg(f.moscaY)
            .arg(QString::fromStdString(f.fixDeadline));
    }

    if (role == Qt::TextAlignmentRole) {
        if (index.column() == COL_KEY_LENGTH || index.column() == COL_CONFIDENCE)
            return int(Qt::AlignRight | Qt::AlignVCenter);
        return int(Qt::AlignLeft | Qt::AlignVCenter);
    }
    return {};
}

QVariant CbomTableModel::headerData(int section, Qt::Orientation orientation, int role) const {
    if (orientation != Qt::Horizontal || role != Qt::DisplayRole) return {};
    switch (section) {
    case COL_ALGORITHM:       return "Algorithm";
    case COL_TYPE:            return "Family / Type";
    case COL_KEY_LENGTH:      return "Key Length";
    case COL_QUANTUM_RISK:    return "Quantum Risk";
    case COL_CONFIDENCE:      return "Confidence";
    case COL_MOSCA_URGENCY:   return "Mosca Fix Priority";
    case COL_PQC_REPLACEMENT: return "Recommended PQC Migration Path";
    case COL_FILE_LINE:       return "File & Line";
    case COL_DETECTION_STAGE: return "Stage";
    default: return {};
    }
}

void CbomTableModel::addFinding(const ecdat::CryptoFinding& finding) {
    m_allFindings.push_back(finding); rebuildFilter();
}
void CbomTableModel::setFindings(const ecdat::FindingList& findings) {
    m_allFindings = findings; rebuildFilter();
}
void CbomTableModel::clear() {
    beginResetModel(); m_allFindings.clear(); m_filtered.clear(); endResetModel();
}
void CbomTableModel::setFilter(const QString& text) {
    m_filterText = text.toLower(); rebuildFilter();
}

void CbomTableModel::rebuildFilter() {
    beginResetModel();
    m_filtered.clear();
    for (const auto& f : m_allFindings) {
        if (m_filterText.isEmpty()) { m_filtered.push_back(f); continue; }
        QString hay = (QString::fromStdString(f.algorithmName)
                     + QString::fromStdString(f.filePath)
                     + QString::fromStdString(f.confidence)
                     + QString::fromStdString(f.scannerSource)
                     + QString::fromStdString(f.fixDeadline)
                     + QString::fromStdString(f.pqcReplacement)
                     + riskText(f.riskLevel)).toLower();
        if (hay.contains(m_filterText)) m_filtered.push_back(f);
    }
    endResetModel();
}

const ecdat::CryptoFinding& CbomTableModel::findingAt(int row) const { return m_filtered.at(row); }

QColor CbomTableModel::riskColor(ecdat::RiskLevel r) const {
    switch (r) {
    case ecdat::RiskLevel::CRITICAL: return QColor("#EF4444");
    case ecdat::RiskLevel::MODERATE: return QColor("#F59E0B");
    default:                         return QColor("#10B981");
    }
}

QString CbomTableModel::riskText(ecdat::RiskLevel r) const {
    switch (r) {
    case ecdat::RiskLevel::CRITICAL: return "CRITICAL";
    case ecdat::RiskLevel::MODERATE: return "MODERATE";
    default:                         return "SAFE";
    }
}

QString CbomTableModel::modeFromAlgo(const std::string& algo) const {
    QString a = QString::fromStdString(algo).toUpper();
    if (a.contains("GCM"))  return "GCM";
    if (a.contains("CBC"))  return "CBC";
    if (a.contains("ECB"))  return "ECB";
    if (a.contains("CTR"))  return "CTR";
    if (a.contains("CFB"))  return "CFB";
    if (a.contains("CCM"))  return "CCM";
    return "N/A";
}

QString CbomTableModel::stageFromType(ecdat::FindingType t) const {
    switch (t) {
    case ecdat::FindingType::ALGORITHM_USAGE:   return "AST Parser";
    case ecdat::FindingType::BINARY_SIGNATURE:  return "YARA Scanner";
    case ecdat::FindingType::KEY_MATERIAL:      return "Key Scanner";
    case ecdat::FindingType::LIBRARY_IMPORT:    return "Dependency Scanner";
    case ecdat::FindingType::PROTOCOL_CONFIG:   return "Config Scanner";
    default:                                    return "ML Triage";
    }
}
