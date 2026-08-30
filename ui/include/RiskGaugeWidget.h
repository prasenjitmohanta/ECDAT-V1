#pragma once

#include <QWidget>
#include "../../core/include/MoscaEngine.h"

class RiskGaugeWidget : public QWidget {
    Q_OBJECT

public:
    explicit RiskGaugeWidget(QWidget* parent = nullptr);
    void setRiskScore(double score);
    void setStatus(ecdat::MoscaStatus status);
    void setDarkMode(bool isDark);

protected:
    void paintEvent(QPaintEvent* event) override;

private:
    double             m_riskScore{0.0};
    ecdat::MoscaStatus m_status{ecdat::MoscaStatus::GREEN_SAFE};
    bool               m_isDarkMode{false};
};
