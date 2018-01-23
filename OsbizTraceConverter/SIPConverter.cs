using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.IO;
using System.Text.RegularExpressions;
using System.Threading;
using System.ComponentModel;

namespace OsbizTraceConverter
{
    public delegate void StatusChangedDelegate(object Sender, string status);

    class SIPConverter
    {
        private BackgroundWorker bw;

        public string activeFile { get; set; }
        public string linesRead { get; set; }

        private byte beforeProgress = 0;
        private byte currentProgress = 0;

        private long fileSize = 0;
        private long pos = 0;
        private long linesWrite = 0;
        private long sipMessages = 0;

        private string inputFolder;
        private string fileFilter;
        private string outputFilename;

        private string regexStart = "\\(SIP_SA \\[ldh:([\\d\\.]+)\\] [0-9x]+ \"(\\d+)\\/(\\d+)\\/(\\d+) (\\d+):(\\d+):(\\d+).(\\d+)\" .*";
        private string regexEnd = "(<<OUT-END>>|>>IN-END<<)";
        private int maxLines = 100;

        private List<string> cache = new List<string>();

        private StreamReader reader;
        private FileStream writer;

        public long FileSize { get => fileSize; }
        public long Pos { get => pos; }
        public long LinesWrite { get => linesWrite; }
        public string InputFolder { get => inputFolder; set => inputFolder = value; }
        public string FileFilter { get => fileFilter; set => fileFilter = value; }
        public string OutputFilename { get => outputFilename; set => outputFilename = value; }
        public string RegexStart { get => regexStart; set => regexStart = value; }
        public string RegexEnd { get => regexEnd; set => regexEnd = value; }
        public List<string> Cache { get => cache; set => cache = value; }
        public byte CurrentProgress { get => currentProgress; }
        public long SipMessages { get => sipMessages; }

        public SIPConverter(BackgroundWorker bw)
        {
            this.bw = bw;
        }

        public void doWork()
        {
            writer = new FileStream(outputFilename, FileMode.Create, FileAccess.Write);
            byte[] pcapHeader = PcapGenerator.getPcapHeader();
            writer.Write(pcapHeader, 0, pcapHeader.Length);

            string[] files = Directory.GetFiles(this.inputFolder, this.fileFilter, SearchOption.AllDirectories);

            PcapGenerator generator = new PcapGenerator();

            foreach (string filename in files)
            {
                bw.ReportProgress(0);

                StringBuilder cache = new StringBuilder();
                FileInfo info = new FileInfo(filename);

                activeFile = filename;
                fileSize = info.Length;

                FileStream fileStream = new FileStream(filename, FileMode.Open, FileAccess.Read);
                BufferedStream bs = new BufferedStream(fileStream);
                reader = new StreamReader(fileStream);

                if (reader == null || writer == null)
                    throw new Exception("Reader or Writer is null");

                string line;

                MatchCollection l1 = null;
                MatchCollection fromMatch = null;
                MatchCollection toMatch = null;
                bool inner = false;
                int actline = 0;

                while ((line = reader.ReadLine()) != null)
                {
                    pos += System.Text.ASCIIEncoding.ASCII.GetByteCount(line);
                    linesWrite++;
                    if (!inner)
                    {
                        if (line.StartsWith("(SIP_SA"))
                        {
                            string localRegex = "\\(SIP_SA \\[ldh:([\\d\\.]+)\\] [0-9a-fA-Fx]+ \"(\\d+)\\/(\\d+)\\/(\\d+) (\\d+):(\\d+):(\\d+).(\\d+)\" .*";

                            string fromRegex = "from (?:localAddr=)?([\\d\\.]+):(\\d+)";
                            string toRegex = "to (?:localAddr=)?([\\d\\.]+):(\\d+)";

                            l1 = Regex.Matches(line, localRegex);

                            if (l1 != null)
                            {
                                cache.Clear();
                                string nline = reader.ReadLine();
                                pos += System.Text.ASCIIEncoding.ASCII.GetByteCount(nline);

                                fromMatch = Regex.Matches(nline, fromRegex);
                                toMatch = Regex.Matches(nline, toRegex);

                                inner = (fromMatch.Count > 0 && toMatch.Count > 0);
                            }
                        }
                    }
                    else
                    {
                        bool gotEnd = Regex.IsMatch(line, RegexEnd);
                        if (!gotEnd)
                        {
                            if (actline > maxLines)
                            {
                                inner = false;
                                actline = 0;
                            }
                            else
                            {
                                cache.AppendLine(line);
                                actline++;
                            }
                        }
                        else
                        {
                            sipMessages++;
                            PcapDataHeader fdp = generator.getPacket(l1, fromMatch, toMatch, cache.ToString());
                            byte[] wb = fdp.toByte();
                            writer.Write(wb, 0, wb.Length);
                            cache.Clear();
                            inner = false;
                            actline = 0;
                        }
                    }
                    this.beforeProgress = this.CurrentProgress;
                    this.currentProgress = (byte)(pos / (this.fileSize / 100));

                    if (this.beforeProgress != this.CurrentProgress)
                        bw.ReportProgress(this.currentProgress);
                }
                this.reader.Close();
                bs.Close();
                fileStream.Close();
                pos = 0;
            }
            this.writer.Close();
        }
    }
}
