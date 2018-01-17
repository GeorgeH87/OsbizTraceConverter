using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;
using Microsoft.Win32;
using System.Windows.Forms;
using System.ComponentModel;

namespace OsbizTraceConverter
{
    /// <summary>
    /// Interaktionslogik für MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        BackgroundWorker bw = new BackgroundWorker();
        SIPConverter sc;

        string activeFile = null;

        public MainWindow()
        {
            InitializeComponent();
            bw.DoWork += Bw_DoWork;
            bw.ProgressChanged += Bw_ProgressChanged;
            bw.RunWorkerCompleted += Bw_RunWorkerCompleted;
            bw.WorkerReportsProgress = true;
            sc = new SIPConverter(bw);
        }

        private void Bw_RunWorkerCompleted(object sender, RunWorkerCompletedEventArgs e)
        {
            TextBlock_Messages.Text += "FINISHED";
            TextBlock_Messages.Text += "\nLINES: " + sc.LinesWrite;
            TextBlock_Messages.Text += "\nSIP MESSAGES: " + sc.SipMessages;
            TextBlock_Messages.Text += "\n\n";
            ProgressBar_File.Value = 0;
        }

        private void Bw_ProgressChanged(object sender, ProgressChangedEventArgs e)
        {
            if (sc.activeFile != activeFile)
            {
                activeFile = sc.activeFile;
                TextBlock_Messages.Text += "reading File " + activeFile + "\n";
            }

            ProgressBar_File.Value = sc.CurrentProgress;
        }

        private void Bw_DoWork(object sender, DoWorkEventArgs e)
        {
            sc.doWork();
        }

        private void Button_FolderInput_Click(object sender, RoutedEventArgs e)
        {
            FolderBrowserDialog fbd = new FolderBrowserDialog();
            fbd.ShowDialog();
            TextBox_FolderInput.Text = fbd.SelectedPath;
        }

        private void Button_Outputfile_Click(object sender, RoutedEventArgs e)
        {
            Microsoft.Win32.SaveFileDialog sf = new Microsoft.Win32.SaveFileDialog();
            sf.Filter = "*.pcap|*.pcap";
            sf.FileOk += Sf_FileOk;
            sf.ShowDialog();
        }

        private void Sf_FileOk(object sender, System.ComponentModel.CancelEventArgs e)
        {
            TextBox_Outputfile.Text = ((Microsoft.Win32.SaveFileDialog)sender).FileName;
        }

        private void Convert_Click(object sender, RoutedEventArgs e)
        {
            sc.InputFolder = TextBox_FolderInput.Text;
            sc.OutputFilename = TextBox_Outputfile.Text;
            sc.FileFilter = TextBox_FolderFilter.Text;
            bw.RunWorkerAsync();
        }
       
    }
}
