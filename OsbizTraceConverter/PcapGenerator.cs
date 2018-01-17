using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using System.Text.RegularExpressions;

namespace OsbizTraceConverter
{
    class fullDataPacket
    {
        public PcapDataHeader pcapDataHeader { get; set; }
        public LinuxCookedHeader linuxCookedHeader { get; set; }
        public IPHeader IPHeader { get; set; }
        public UDPHeader uDPHeader { get; set; }
        public string sipMessage { get; set; }

        public byte[] toByte()
        {
            List<byte> bytes = new List<byte>();
            bytes.AddRange(pcapDataHeader.toByte());
            bytes.AddRange(linuxCookedHeader.toByte());
            bytes.AddRange(IPHeader.toByte());
            bytes.AddRange(uDPHeader.toByte());
            bytes.AddRange(ASCIIEncoding.ASCII.GetBytes(sipMessage));
            return bytes.ToArray();
        }
    }

    class LinuxCookedHeader
    {
        UInt16 packetType;
        UInt16 addressType;
        UInt16 addressLength;
        byte[] source; //6byte
        UInt16 unused;
        UInt16 protocol;
        IPHeader ipHeader;

        public LinuxCookedHeader(UInt16 packetType,
        UInt16 addressType,
        UInt16 addressLength,
        byte[] source, //6byte
        UInt16 unused,
        UInt16 protocol,
        IPHeader ipHeader)
        {
            this.packetType = packetType;
            this.addressType = addressType;
            this.addressLength = addressLength;
            this.source = source;
            this.unused = unused;
            this.protocol = protocol;
            this.ipHeader = ipHeader;
        }

        public byte[] toByte()
        {
            List<byte> bytes = new List<byte>();
            bytes.AddRange(BitConverter.GetBytes(packetType).Reverse());
            bytes.AddRange(BitConverter.GetBytes(addressType).Reverse());
            bytes.AddRange(BitConverter.GetBytes(addressLength).Reverse());
            bytes.AddRange(source);
            bytes.AddRange(BitConverter.GetBytes(unused).Reverse());
            bytes.AddRange(BitConverter.GetBytes(protocol).Reverse());
            bytes.AddRange(ipHeader.toByte());
            return bytes.ToArray();
        }
    }

    class IPHeader
    {
        byte versionLength;
        byte dspField;
        UInt16 identification;
        UInt16 fragment;
        byte timeToLive;
        byte protocol;
        UInt16 checksum;
        IPAddress sourceIP;
        IPAddress destinationIP;
        UDPHeader udpHeader;

        public IPHeader(byte version,
            byte dspField,
            UInt16 identification,
            UInt16 fragment,
            byte timeToLive,
            byte protocol,
            UInt16 checksum,
            IPAddress sourceIP,
            IPAddress destinationIP,
            UDPHeader udpHeader)
        {
            this.versionLength = (byte)(version << 4 | 5);
            this.dspField = dspField;
            this.identification = identification;
            this.fragment = fragment;
            this.timeToLive = timeToLive;
            this.protocol = protocol;
            this.checksum = checksum;
            this.sourceIP = sourceIP;
            this.destinationIP = destinationIP;
            this.udpHeader = udpHeader;
        }

        public byte[] toByte()
        {
            byte[] data = udpHeader.toByte();
            UInt16 totalLength = (UInt16)(data.Length + 20);

            List<byte> bytes = new List<byte>();
            bytes.Add(versionLength);
            bytes.Add(dspField);
            bytes.AddRange(BitConverter.GetBytes(totalLength).Reverse());
            bytes.AddRange(BitConverter.GetBytes(identification).Reverse());
            bytes.AddRange(BitConverter.GetBytes(fragment).Reverse());
            bytes.Add(timeToLive);
            bytes.Add(protocol);
            bytes.AddRange(BitConverter.GetBytes(checksum).Reverse());
            bytes.AddRange(sourceIP.GetAddressBytes().Reverse());
            bytes.AddRange(destinationIP.GetAddressBytes().Reverse());
            bytes.AddRange(data);
            return bytes.ToArray();
        }
    }

    class UDPHeader
    {
        UInt16 sourcePort;
        UInt16 destinationPort;
        UInt16 checksum = 0x1111;
        string sipMessage;

        public UDPHeader(UInt16 sourcePort,
        UInt16 destinationPort,
        string sipMessage)
        {
            this.sourcePort = sourcePort;
            this.destinationPort = destinationPort;
            this.sipMessage = sipMessage;
        }

        public byte[] toByte()
        {
            byte[] data = ASCIIEncoding.ASCII.GetBytes(sipMessage);
            UInt16 length = (UInt16)(data.Length + 8);

            List<byte> bytes = new List<byte>();
            bytes.AddRange(BitConverter.GetBytes(sourcePort).Reverse());
            bytes.AddRange(BitConverter.GetBytes(destinationPort).Reverse());
            bytes.AddRange(BitConverter.GetBytes(length).Reverse());
            bytes.AddRange(BitConverter.GetBytes(checksum).Reverse());
            bytes.AddRange(data);
            return bytes.ToArray();
        }
    }

    class PcapHeader
    {
        UInt32 magic_number;
        UInt16 version_major;
        UInt16 version_minor;
        UInt32 thiszone;
        UInt32 sigfigs;
        UInt32 snaplen;
        UInt32 network;

        public PcapHeader(UInt32 magic_number,
        UInt16 version_major,
        UInt16 version_minor,
        UInt32 thiszone,
        UInt32 sigfigs,
        UInt32 snaplen,
        UInt32 network)
        {
            this.magic_number = magic_number;
            this.version_major = version_major;
            this.version_minor = version_minor;
            this.thiszone = thiszone;
            this.sigfigs = sigfigs;
            this.snaplen = snaplen;
            this.network = network;
        }

        public byte[] toByte()
        {
            List<byte> bytes = new List<byte>();
            bytes.AddRange(BitConverter.GetBytes(magic_number).Reverse());
            bytes.AddRange(BitConverter.GetBytes(version_major).Reverse());
            bytes.AddRange(BitConverter.GetBytes(version_minor).Reverse());
            bytes.AddRange(BitConverter.GetBytes(thiszone).Reverse());
            bytes.AddRange(BitConverter.GetBytes(sigfigs).Reverse());
            bytes.AddRange(BitConverter.GetBytes(snaplen).Reverse());
            bytes.AddRange(BitConverter.GetBytes(network).Reverse());
            return bytes.ToArray();
        }
    }

    class PcapDataHeader
    {
        UInt32 ts_sec;
        UInt32 ts_usec;
        LinuxCookedHeader linuxCookedHeader;

        public PcapDataHeader(UInt32 ts_sec,
        UInt32 ts_usec,
        LinuxCookedHeader linuxCookedHeader)
        {
            this.ts_sec = ts_sec;
            this.ts_usec = ts_usec;
            this.linuxCookedHeader = linuxCookedHeader;
        }

        public byte[] toByte()
        {
            byte[] data = linuxCookedHeader.toByte();
            UInt32 length = (UInt32)data.Length;

            List<byte> bytes = new List<byte>();
            bytes.AddRange(BitConverter.GetBytes(ts_sec).Reverse());
            bytes.AddRange(BitConverter.GetBytes(ts_usec).Reverse());
            bytes.AddRange(BitConverter.GetBytes(length).Reverse());
            bytes.AddRange(BitConverter.GetBytes(length).Reverse());
            bytes.AddRange(data);
            return bytes.ToArray();
        }
    }

    class PcapGenerator
    {
        private Dictionary<IPAddress, ushort> counterIP = new Dictionary<IPAddress, ushort>();

        public static byte[] getPcapHeader()
        {
            return new PcapHeader(0xA1B2C3D4, 2, 4, 0, 0, 0xFFFF, 0x71).toByte();
        }

        public PcapDataHeader getPacket(MatchCollection l1, MatchCollection fromMatch, MatchCollection toMatch, string sip)
        {
            int sipLength = ASCIIEncoding.ASCII.GetByteCount(sip) - 1;

            if (l1.Count == 0) return null;
            if (fromMatch.Count == 0) return null;
            if (toMatch.Count == 0) return null;

            IPAddress localAddress = IPAddress.Parse(l1[0].Groups[1].Value);
            int month = int.Parse(l1[0].Groups[2].Value);
            int day = int.Parse(l1[0].Groups[3].Value);
            int year = int.Parse(l1[0].Groups[4].Value);
            int hour = int.Parse(l1[0].Groups[5].Value);
            int minute = int.Parse(l1[0].Groups[6].Value);
            int second = int.Parse(l1[0].Groups[7].Value);
            uint microsecond = uint.Parse(l1[0].Groups[8].Value);

            IPAddress fromAddress = IPAddress.Parse(fromMatch[0].Groups[1].Value);
            UInt16 fromPort = UInt16.Parse(fromMatch[0].Groups[2].Value);

            IPAddress toAddress = IPAddress.Parse(toMatch[0].Groups[1].Value);
            UInt16 toPort = UInt16.Parse(toMatch[0].Groups[2].Value);

            byte[] rawMAC;

            ushort ipCounter = 0;
            ushort packetType = 0;

            rawMAC = getMac(fromAddress);

            if (localAddress.Equals(fromAddress))
                packetType = 4;
            else
                packetType = 0;

            if (counterIP.ContainsKey(fromAddress))
            {
                ipCounter = counterIP[fromAddress];
            }
            else
            {
                ipCounter = 0;
                counterIP.Add(fromAddress, ipCounter);
            }

            DateTime dt = new DateTime(year, month, day, hour, minute, second);
            DateTime ft = new DateTime(1970, 1, 1);

            uint seconds = (uint)dt.Subtract(ft).TotalSeconds;

            PcapDataHeader rtn = new PcapDataHeader(seconds, microsecond,
                new LinuxCookedHeader(packetType, 1, 6, rawMAC, 0, 2048,
                new IPHeader(4, 0, ipCounter, 0, 58, 0x11, 0, fromAddress, toAddress,
                new UDPHeader(fromPort, toPort, sip))));

            byte[] rtnBytes = rtn.toByte();

            return rtn;
        }

        private static byte[] getMac(IPAddress address)
        {
            byte[] rawIPfrom = address.GetAddressBytes();
            byte[] rawMACfrom = { 0x00, 0x00, rawIPfrom[0], rawIPfrom[1], rawIPfrom[2], rawIPfrom[3] };
            return rawMACfrom;
        }
    }
}
