using System;
using System.Drawing;
using System.IO.MemoryMappedFiles;
using System.Windows.Forms;

class TempWidget : Form
{
    NotifyIcon tray;
    Label lbl;
    System.Windows.Forms.Timer t;
    int currentTemp = -1;

    public TempWidget()
    {
        Text = "Temp CPU";
        FormBorderStyle = FormBorderStyle.None;
        TopMost = true;
        ShowInTaskbar = false;
        StartPosition = FormStartPosition.Manual;
        Location = new Point(20, 20);
        BackColor = Color.FromArgb(24, 24, 24);

        lbl = new Label();
        lbl.Font = new Font("Segoe UI", 22, FontStyle.Bold);
        lbl.ForeColor = Color.LimeGreen;
        lbl.TextAlign = ContentAlignment.MiddleCenter;
        lbl.Dock = DockStyle.Fill;
        Controls.Add(lbl);
        ClientSize = new Size(150, 60);

        var cm = new ContextMenuStrip();
        cm.Items.Add("Quitter", null, (s, e) => Application.Exit());
        ContextMenuStrip = cm;

        tray = new NotifyIcon();
        tray.Icon = SystemIcons.Information;
        tray.Text = "Temp CPU - Clic droit pour quitter";
        tray.Visible = true;
        tray.ContextMenuStrip = cm;

        t = new System.Windows.Forms.Timer();
        t.Interval = 1000;
        t.Tick += (s, e) => UpdateTemp();
        t.Start();
        UpdateTemp();
    }

    void UpdateTemp()
    {
        byte[] buf = null;
        bool ok = false;
        foreach (string name in new string[] { "CoreTempMappingObjectEx", "CoreTempMappingObject" })
        {
            try
            {
                using (var mmf = MemoryMappedFile.OpenExisting(name, MemoryMappedFileRights.Read))
                using (var view = mmf.CreateViewAccessor(0, 0, MemoryMappedFileAccess.Read))
                {
                    long size = Math.Min(view.Capacity, 4096);
                    buf = new byte[size];
                    view.ReadArray(0, buf, 0, (int)size);
                }
                ok = true;
                break;
            }
            catch { }
        }

        if (!ok || buf == null || buf.Length < 2600)
        {
            lbl.Text = "-- C";
            lbl.ForeColor = Color.Gray;
            return;
        }

        int coreCnt = BitConverter.ToInt32(buf, 1536);
        if (coreCnt <= 0 || coreCnt > 128)
        {
            lbl.Text = "-- C";
            lbl.ForeColor = Color.Gray;
            return;
        }

        bool delta = buf[2685] == 1;
        bool fahr = buf[2684] == 1;
        int tjMax = BitConverter.ToInt32(buf, 1024);

        double sum = 0;
        for (int i = 0; i < coreCnt; i++)
        {
            double t = BitConverter.ToSingle(buf, 1544 + i * 4);
            if (delta) t = tjMax - t;
            sum += t;
        }
        double avg = sum / coreCnt;
        if (fahr) avg = avg * 9.0 / 5.0 + 32.0;

        currentTemp = (int)Math.Round(avg);
        lbl.Text = "CPU " + currentTemp + " C";
        lbl.ForeColor = currentTemp >= 85 ? Color.Red : (currentTemp >= 75 ? Color.Orange : Color.LimeGreen);
        tray.Text = "Temp CPU moyenne: " + currentTemp + " C - clic droit pour quitter";
    }

    protected override void OnMouseDown(MouseEventArgs e)
    {
        base.OnMouseDown(e);
        if (e.Button == MouseButtons.Left)
        {
            ReleaseCapture();
            SendMessage(Handle, 0xA1, (IntPtr)2, IntPtr.Zero);
        }
    }

    [System.Runtime.InteropServices.DllImport("user32.dll")]
    static extern bool ReleaseCapture();
    [System.Runtime.InteropServices.DllImport("user32.dll")]
    static extern IntPtr SendMessage(IntPtr hWnd, int Msg, IntPtr wParam, IntPtr lParam);
}

class Program
{
    [STAThread]
    static void Main()
    {
        Application.EnableVisualStyles();
        Application.SetCompatibleTextRenderingDefault(false);
        Application.Run(new TempWidget());
    }
}
