// ================================================================
//  RiskGaugeWidget.cpp  —  Minimalist Threat Index Dial
//  Adaptive for both Light and Dark Mode
// ================================================================

#include "../include/RiskGaugeWidget.h"
#include <QPainter>
#include <QPainterPath>
#include <QRectF>
#include <QPointF>
#include <QtMath>
#include <algorithm>
#include <cmath>

static constexpr double GAUGE_START_DEG = 210.0;
static constexpr double GAUGE_SPAN_DEG  = -240.0;

static double scoreToAngle(double score) {
    double clamped = std::clamp(score, 0.0, 2.0);
    return GAUGE_START_DEG + (clamped / 2.0) * GAUGE_SPAN_DEG;
}

static double toRadians(double deg) {
    return deg * M_PI / 180.0;
}

RiskGaugeWidget::RiskGaugeWidget(QWidget* parent) : QWidget(parent) {
    setMinimumSize(260, 200);
    setAttribute(Qt::WA_OpaquePaintEvent, false);
}

void RiskGaugeWidget::setRiskScore(double score) {
    m_riskScore = score;
    update();
}

void RiskGaugeWidget::setStatus(ecdat::MoscaStatus status) {
    m_status = status;
    update();
}

void RiskGaugeWidget::setDarkMode(bool isDark) {
    m_isDarkMode = isDark;
    update();
}

void RiskGaugeWidget::paintEvent(QPaintEvent*) {
    QPainter p(this);
    p.setRenderHint(QPainter::Antialiasing);
    p.setRenderHint(QPainter::TextAntialiasing);

    const QRectF bounds = rect();
    const double cx = bounds.width() / 2.0;
    const double cy = bounds.height() * 0.58;
    const double radius = qMin(bounds.width() * 0.40, cy * 0.90);
    const QPointF center(cx, cy);
    const QRectF arcRect(cx - radius, cy - radius, 2.0 * radius, 2.0 * radius);

    // 1. Base track
    QColor baseTrackColor = m_isDarkMode ? QColor("#334155") : QColor("#E2E8F0");
    QPen basePen(baseTrackColor, 12, Qt::SolidLine, Qt::RoundCap);
    p.setPen(basePen);
    p.drawArc(arcRect, int(GAUGE_START_DEG * 16), int(GAUGE_SPAN_DEG * 16));

    // 2. Colored rating zones
    struct Zone { double s; double span; QColor col; };
    Zone zones[] = {
        { 210.0, -96.0, QColor("#10B981") }, // 0.0 - 0.8  Green
        { 114.0, -24.0, QColor("#F59E0B") }, // 0.8 - 1.0  Amber
        {  90.0,-120.0, QColor("#EF4444") }  // 1.0 - 2.0  Red
    };

    for (const auto& z : zones) {
        p.setPen(QPen(z.col, 10, Qt::SolidLine, Qt::FlatCap));
        p.drawArc(arcRect, int(z.s * 16), int(z.span * 16));
    }

    // 3. Ticks and Labels
    struct Tick { double val; const char* text; };
    Tick ticks[] = {
        { 0.0, "0.0" }, { 0.5, "0.5" }, { 1.0, "1.0" }, { 1.5, "1.5" }, { 2.0, "2.0" }
    };

    p.setFont(QFont("Arial", 8, QFont::Bold));
    QColor tickColor = m_isDarkMode ? QColor("#94A3B8") : QColor("#64748B");
    QColor tickLabelColor = m_isDarkMode ? QColor("#CBD5E1") : QColor("#475569");

    for (const auto& t : ticks) {
        double a = toRadians(scoreToAngle(t.val));
        double co = qCos(a), si = qSin(a);

        QPointF p1(cx + (radius - 12) * co, cy - (radius - 12) * si);
        QPointF p2(cx + (radius + 4)  * co, cy - (radius + 4)  * si);

        p.setPen(QPen(tickColor, 1.5));
        p.drawLine(p1, p2);

        QPointF pl(cx + (radius - 24) * co - 12, cy - (radius - 24) * si - 6);
        p.setPen(tickLabelColor);
        p.drawText(QRectF(pl, QSizeF(24, 12)), Qt::AlignCenter, t.text);
    }

    // 4. Pointer Needle
    double needleAngle = toRadians(scoreToAngle(m_riskScore));
    double nCos = qCos(needleAngle), nSin = qSin(needleAngle);
    QPointF tip(cx + (radius - 6) * nCos, cy - (radius - 6) * nSin);

    QColor needleColor = (m_status == ecdat::MoscaStatus::RED_ALERT) ? QColor("#EF4444")
                       : (m_status == ecdat::MoscaStatus::AMBER_WARNING) ? QColor("#F59E0B")
                       : QColor("#10B981");

    p.setPen(QPen(needleColor, 2.5, Qt::SolidLine, Qt::RoundCap));
    p.drawLine(center, tip);

    // Pivot Circle
    QColor pivotFill = m_isDarkMode ? QColor("#0F172A") : QColor("#1E293B");
    QColor pivotRing = m_isDarkMode ? QColor("#475569") : QColor("#FFFFFF");
    p.setBrush(pivotFill);
    p.setPen(QPen(pivotRing, 2));
    p.drawEllipse(center, 7.0, 7.0);

    // 5. Rating Number & Verdict Text
    QString scoreStr = QString::number(m_riskScore, 'f', 2);
    QRectF numRect(cx - 60, cy - 2, 120, 32);

    p.setFont(QFont("Arial", 22, QFont::Bold));
    p.setPen(needleColor);
    p.drawText(numRect, Qt::AlignCenter, scoreStr);

    p.setFont(QFont("Arial", 8, QFont::Bold));
    p.setPen(m_isDarkMode ? QColor("#94A3B8") : QColor("#64748B"));
    p.drawText(QRectF(cx - 60, cy - 20, 120, 14), Qt::AlignCenter, "THREAT RATIO");

    // Verdict Badge
    QString badgeText;
    switch (m_status) {
        case ecdat::MoscaStatus::RED_ALERT:
            badgeText = "RED ALERT (X + Y > Z)";
            break;
        case ecdat::MoscaStatus::AMBER_WARNING:
            badgeText = "WARNING (X + Y ≈ Z)";
            break;
        default:
            badgeText = "SAFE (X + Y < Z)";
            break;
    }

    QRectF badgeRect(cx - 75, cy + 34, 150, 18);
    p.setPen(QPen(needleColor, 1));
    p.setBrush(QColor(needleColor.red(), needleColor.green(), needleColor.blue(), m_isDarkMode ? 35 : 20));
    p.drawRoundedRect(badgeRect, 3, 3);

    p.setFont(QFont("Arial", 7, QFont::Bold));
    p.setPen(needleColor);
    p.drawText(badgeRect, Qt::AlignCenter, badgeText);
}
