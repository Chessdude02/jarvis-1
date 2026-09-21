"""The desktop entity: a small frameless, translucent, always-on-top,
draggable orb that visually reflects EntityState. This is the "persistent
computer companion" surface -- clicking it (without having dragged it)
opens the chat window.
"""
from __future__ import annotations

from PySide6.QtCore import QPoint, QRectF, Qt, QTimer, Signal
from PySide6.QtGui import QColor, QMouseEvent, QPainter, QPaintEvent, QRadialGradient
from PySide6.QtWidgets import QWidget

from jarvis.core.orchestrator import EntityState

_STATE_COLORS: dict[EntityState, tuple[QColor, QColor]] = {
    EntityState.IDLE: (QColor(40, 70, 110), QColor(20, 30, 45)),
    EntityState.LISTENING: (QColor(60, 170, 255), QColor(20, 40, 70)),
    EntityState.THINKING: (QColor(120, 130, 255), QColor(25, 25, 60)),
    EntityState.SEARCHING: (QColor(80, 200, 220), QColor(15, 45, 55)),
    EntityState.EXECUTING: (QColor(255, 180, 60), QColor(60, 40, 10)),
    EntityState.WAITING_FOR_APPROVAL: (QColor(255, 140, 40), QColor(60, 35, 5)),
    EntityState.SUCCESS: (QColor(80, 230, 140), QColor(15, 45, 25)),
    EntityState.ERROR: (QColor(255, 80, 80), QColor(55, 15, 15)),
}

_ANIMATED_STATES = {EntityState.THINKING, EntityState.SEARCHING, EntityState.EXECUTING, EntityState.WAITING_FOR_APPROVAL}


class EntityWidget(QWidget):
    clicked = Signal()
    moved = Signal(QPoint)

    def __init__(self, size_px: int = 96, parent=None) -> None:
        super().__init__(parent)
        self._size = size_px
        self._state = EntityState.IDLE
        self._phase = 0.0
        self._drag_origin: QPoint | None = None
        self._press_pos: QPoint | None = None
        self._dragged = False

        self.setFixedSize(size_px, size_px)
        self.setWindowFlags(Qt.FramelessWindowHint | Qt.WindowStaysOnTopHint | Qt.Tool)
        self.setAttribute(Qt.WA_TranslucentBackground)
        self.setAttribute(Qt.WA_NoSystemBackground)

        self._timer = QTimer(self)
        self._timer.timeout.connect(self._tick)
        self._timer.start(33)  # ~30 fps only while an animated state is active

    # -- state -----------------------------------------------------------

    def set_state(self, state: EntityState) -> None:
        self._state = state
        self.update()

    @property
    def state(self) -> EntityState:
        return self._state

    def _tick(self) -> None:
        if self._state in _ANIMATED_STATES:
            self._phase = (self._phase + 0.06) % (2 * 3.14159265)
            self.update()

    # -- painting ----------------------------------------------------------

    def paintEvent(self, event: QPaintEvent) -> None:
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        rect = QRectF(4, 4, self._size - 8, self._size - 8)
        outer, inner = _STATE_COLORS[self._state]

        gradient = QRadialGradient(rect.center(), rect.width() / 2)
        gradient.setColorAt(0.0, outer)
        gradient.setColorAt(1.0, inner)
        painter.setPen(Qt.NoPen)
        painter.setBrush(gradient)
        painter.drawEllipse(rect)

        if self._state in _ANIMATED_STATES:
            import math
            painter.setPen(Qt.NoPen)
            painter.setBrush(Qt.NoBrush)
            pen = painter.pen()
            arc_color = QColor(outer)
            arc_color.setAlpha(220)
            from PySide6.QtGui import QPen
            painter.setPen(QPen(arc_color, 3))
            start_angle = int(math.degrees(self._phase) * 16)
            painter.drawArc(rect.adjusted(-2, -2, 2, 2), start_angle, 90 * 16)
        painter.end()

    # -- drag / click --------------------------------------------------------

    def mousePressEvent(self, event: QMouseEvent) -> None:
        if event.button() == Qt.LeftButton:
            self._press_pos = event.globalPosition().toPoint()
            self._drag_origin = self.pos()
            self._dragged = False

    def mouseMoveEvent(self, event: QMouseEvent) -> None:
        if self._press_pos is None:
            return
        delta = event.globalPosition().toPoint() - self._press_pos
        if delta.manhattanLength() > 4:
            self._dragged = True
            self.move(self._drag_origin + delta)

    def mouseReleaseEvent(self, event: QMouseEvent) -> None:
        if event.button() == Qt.LeftButton:
            if self._dragged:
                self.moved.emit(self.pos())
            else:
                self.clicked.emit()
            self._press_pos = None
