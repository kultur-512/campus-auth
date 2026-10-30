using System.Drawing.Drawing2D;

namespace CampusAuth;

/// <summary>全局配色，改这里就能换主题。</summary>
internal static class Palette
{
    public static readonly Color Bg = Color.FromArgb(244, 246, 249);
    public static readonly Color Card = Color.White;
    public static readonly Color Border = Color.FromArgb(229, 232, 238);
    public static readonly Color Text = Color.FromArgb(26, 31, 40);
    public static readonly Color Muted = Color.FromArgb(108, 116, 132);
    public static readonly Color Primary = Color.FromArgb(10, 124, 255);
    public static readonly Color PrimaryHover = Color.FromArgb(32, 141, 255);
    public static readonly Color PrimaryDown = Color.FromArgb(6, 104, 220);
    public static readonly Color Ghost = Color.FromArgb(240, 242, 246);
    public static readonly Color GhostHover = Color.FromArgb(229, 233, 240);
    public static readonly Color GhostDown = Color.FromArgb(216, 221, 230);
    public static readonly Color Success = Color.FromArgb(34, 197, 94);
    public static readonly Color Warn = Color.FromArgb(245, 158, 11);
    public static readonly Color Danger = Color.FromArgb(239, 68, 68);
    public static readonly Color Info = Color.FromArgb(56, 152, 255);
    public static readonly Color HeaderFrom = Color.FromArgb(19, 24, 34);
    public static readonly Color HeaderTo = Color.FromArgb(34, 48, 68);
    public static readonly Color HeaderMuted = Color.FromArgb(148, 162, 184);
}

internal static class Ui
{
    public const string FontFamily = "Microsoft YaHei UI";

    /// <summary>当前控件所在屏幕的缩放比例（96 DPI = 1.0）。</summary>
    public static float DpiScale(Control c) => c.DeviceDpi / 96f;

    public static Font Font(float size, FontStyle style = FontStyle.Regular) => new(FontFamily, size, style);

    public static GraphicsPath Round(Rectangle r, int radius)
    {
        var path = new GraphicsPath();
        int d = Math.Max(1, radius * 2);
        if (d > r.Width) d = r.Width;
        if (d > r.Height) d = r.Height;
        path.AddArc(r.X, r.Y, d, d, 180, 90);
        path.AddArc(r.Right - d, r.Y, d, d, 270, 90);
        path.AddArc(r.Right - d, r.Bottom - d, d, d, 0, 90);
        path.AddArc(r.X, r.Bottom - d, d, d, 90, 90);
        path.CloseFigure();
        return path;
    }

    /// <summary>白色圆角卡片，左上角带小标题。</summary>
    public class Card : Panel
    {
        public string Title = "";

        public Card()
        {
            SetStyle(ControlStyles.UserPaint | ControlStyles.AllPaintingInWmPaint |
                     ControlStyles.OptimizedDoubleBuffer | ControlStyles.ResizeRedraw, true);
            BackColor = Palette.Bg;
        }

        protected override void OnPaint(PaintEventArgs e)
        {
            var g = e.Graphics;
            g.SmoothingMode = SmoothingMode.AntiAlias;
            float s = DpiScale(this);
            var rect = new Rectangle(0, 0, Width - 1, Height - 1);
            using var path = Round(rect, (int)(12 * s));
            using var fill = new SolidBrush(Palette.Card);
            g.FillPath(fill, path);
            using var pen = new Pen(Palette.Border);
            g.DrawPath(pen, path);

            if (Title.Length > 0)
            {
                using var font = Font(9F, FontStyle.Bold);
                using var brush = new SolidBrush(Palette.Muted);
                g.DrawString(Title, font, brush, 16 * s, 12 * s);
            }
            base.OnPaint(e);
        }
    }

    /// <summary>扁平圆角按钮，带悬停/按下反馈。</summary>
    public class FlatButton : Button
    {
        public Color Normal = Palette.Ghost;
        public Color Hover = Palette.GhostHover;
        public Color Down = Palette.GhostDown;
        public Color TextColor = Palette.Text;
        public Color SurfaceColor = Palette.Card;
        public int Radius = 8;

        private bool _hover, _down;

        public FlatButton()
        {
            SetStyle(ControlStyles.UserPaint | ControlStyles.AllPaintingInWmPaint |
                     ControlStyles.OptimizedDoubleBuffer | ControlStyles.ResizeRedraw, true);
            FlatStyle = FlatStyle.Flat;
            FlatAppearance.BorderSize = 0;
            Cursor = Cursors.Hand;
            Font = Font(9.5F, FontStyle.Bold);
            BackColor = Color.Transparent;
        }

        protected override void OnMouseEnter(EventArgs e) { _hover = true; Invalidate(); base.OnMouseEnter(e); }
        protected override void OnMouseLeave(EventArgs e) { _hover = false; _down = false; Invalidate(); base.OnMouseLeave(e); }
        protected override void OnMouseDown(MouseEventArgs e) { _down = true; Invalidate(); base.OnMouseDown(e); }
        protected override void OnMouseUp(MouseEventArgs e) { _down = false; Invalidate(); base.OnMouseUp(e); }

        protected override void OnPaint(PaintEventArgs e)
        {
            var g = e.Graphics;
            g.SmoothingMode = SmoothingMode.AntiAlias;
            g.Clear(SurfaceColor);

            Color back = !Enabled ? Color.FromArgb(236, 238, 243)
                : _down ? Down
                : _hover ? Hover
                : Normal;
            Color fore = !Enabled ? Color.FromArgb(146, 153, 166) : TextColor;

            var rect = new Rectangle(0, 0, Width - 1, Height - 1);
            using var path = Round(rect, (int)(Radius * DpiScale(this)));
            using var brush = new SolidBrush(back);
            g.FillPath(brush, path);

            TextRenderer.DrawText(g, Text, Font, rect, fore,
                TextFormatFlags.HorizontalCenter | TextFormatFlags.VerticalCenter | TextFormatFlags.NoPadding);
        }
    }

    /// <summary>顶部深色状态栏，文字与统计直接绘制。</summary>
    public class HeaderPanel : Panel
    {
        private string _state = "未启动";
        private string _detail = "";
        private Color _dot = Color.Gray;
        private string _stat1Caption = "在线时长", _stat1Value = "--";
        private string _stat2Caption = "认证次数", _stat2Value = "0";

        public HeaderPanel()
        {
            SetStyle(ControlStyles.UserPaint | ControlStyles.AllPaintingInWmPaint |
                     ControlStyles.OptimizedDoubleBuffer | ControlStyles.ResizeRedraw, true);
            BackColor = Palette.Bg;
        }

        public void SetStatus(string state, string detail, Color dot)
        {
            _state = state;
            _detail = detail;
            _dot = dot;
            Invalidate();
        }

        public void SetStats(string v1, string v2)
        {
            _stat1Value = v1;
            _stat2Value = v2;
            Invalidate();
        }

        protected override void OnPaint(PaintEventArgs e)
        {
            var g = e.Graphics;
            g.SmoothingMode = SmoothingMode.AntiAlias;
            g.TextRenderingHint = System.Drawing.Text.TextRenderingHint.ClearTypeGridFit;

            float s = DpiScale(this);
            var rect = new Rectangle(0, 0, Width - 1, Height - 1);
            using (var path = Round(rect, (int)(14 * s)))
            using (var brush = new LinearGradientBrush(new Rectangle(0, 0, Width, Height),
                       Palette.HeaderFrom, Palette.HeaderTo, 20f))
            {
                g.FillPath(brush, path);
            }

            // 状态圆点（带光晕）
            using (var glow = new SolidBrush(Color.FromArgb(55, _dot)))
                g.FillEllipse(glow, 22 * s, 44 * s, 26 * s, 26 * s);
            using (var dot = new SolidBrush(_dot))
                g.FillEllipse(dot, 28 * s, 50 * s, 14 * s, 14 * s);

            using (var f = Font(16.5F, FontStyle.Bold))
                g.DrawString(_state, f, Brushes.White, 56 * s, 26 * s);
            using (var f = Font(9F))
            using (var b = new SolidBrush(Palette.HeaderMuted))
                g.DrawString(_detail, f, b, 58 * s, 74 * s);

            // 右侧统计
            int rightX = (int)(Width - 28 * s);
            DrawStat(g, rightX, _stat2Caption, _stat2Value);
            DrawStat(g, rightX - (int)(120 * s), _stat1Caption, _stat1Value);

            base.OnPaint(e);
        }

        private void DrawStat(Graphics g, int rightEdge, string caption, string value)
        {
            using var f1 = Font(8F);
            using var f2 = Font(13F, FontStyle.Bold);
            using var b1 = new SolidBrush(Palette.HeaderMuted);
            using var b2 = new SolidBrush(Color.White);

            var sizeV = g.MeasureString(value, f2);
            var sizeC = g.MeasureString(caption, f1);
            float xV = rightEdge - sizeV.Width;
            float xC = rightEdge - sizeC.Width;
            float s = DpiScale(this);
            g.DrawString(value, f2, b2, xV, 34 * s);
            g.DrawString(caption, f1, b1, xC, 68 * s);
        }
    }
}
