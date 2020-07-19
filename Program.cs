using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net.Sockets;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;

namespace SharpOXID_Find
{
    class Program
    {
        #region OXID 请求解析
        static byte[] buffer_v1 ={ /* Packet 431 */
            0x05, 0x00, 0x0b, 0x03, 0x10, 0x00, 0x00, 0x00,
            0x48, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
            0xb8, 0x10, 0xb8, 0x10, 0x00, 0x00, 0x00, 0x00,
            0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
            0xc4, 0xfe, 0xfc, 0x99, 0x60, 0x52, 0x1b, 0x10,
            0xbb, 0xcb, 0x00, 0xaa, 0x00, 0x21, 0x34, 0x7a,
            0x00, 0x00, 0x00, 0x00, 0x04, 0x5d, 0x88, 0x8a,
            0xeb, 0x1c, 0xc9, 0x11, 0x9f, 0xe8, 0x08, 0x00,
            0x2b, 0x10, 0x48, 0x60, 0x02, 0x00, 0x00, 0x00 };

        static byte[] buffer_v2 ={/* Packet 433 */
            0x05, 0x00, 0x00, 0x03, 0x10, 0x00, 0x00, 0x00,
            0x18, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x00 };
        #endregion

        private static List<string> Network2IpRange(string sNetwork)
        {
            string[] iparray = new string[0];
            List<string> iparrays = iparray.ToList();
            uint ip,        /* ip address */
            mask,       /* subnet mask */
                broadcast,  /* Broadcast address */
                network;    /* Network address */

            int bits;

            string[] elements = sNetwork.Split(new Char[] { '/' });

            ip = IP2Int(elements[0]);
            bits = Convert.ToInt32(elements[1]);

            mask = ~(0xffffffff >> bits);


            network = ip & mask;
            broadcast = network + ~mask;
            uint usableIps = (bits > 30) ? 0 : (broadcast - network - 1);
            Console.WriteLine("[+] ip range {0} - {1} ", IntToIp(network + 1), IntToIp(broadcast - 1));
            for (uint i = 1; i < usableIps + 1; i++)
            {
                //Console.WriteLine(IntToIp(network + i));
                iparrays.Add(IntToIp(network + i));
            }
            return iparrays;
        }

        public static uint IP2Int(string IPNumber)
        {
            uint ip = 0;
            string[] elements = IPNumber.Split(new Char[] { '.' });
            if (elements.Length == 4)
            {
                ip = Convert.ToUInt32(elements[0]) << 24;
                ip += Convert.ToUInt32(elements[1]) << 16;
                ip += Convert.ToUInt32(elements[2]) << 8;
                ip += Convert.ToUInt32(elements[3]);
            }
            return ip;
        }

        public static string IntToIp(uint ipInt)
        {
            StringBuilder sb = new StringBuilder();
            sb.Append((ipInt >> 24) & 0xFF).Append(".");
            sb.Append((ipInt >> 16) & 0xFF).Append(".");
            sb.Append((ipInt >> 8) & 0xFF).Append(".");
            sb.Append(ipInt & 0xFF);
            return sb.ToString();
        }
        public static ArrayList arrayList = new ArrayList();

        /// <summary>
        /// ip处理，线程分配
        /// </summary>
        /// <param name="ip"></param>
        public static void ThreadList(string ip)
        {
            Console.WriteLine("");
            try
            {
                ip = ip.Trim();
                // Console.WriteLine(ip);
                foreach (string s in Network2IpRange(ip))
                {
                    arrayList.Add(new threadStart(s));
                    //Console.WriteLine(s);
                }
                Thread[] array = new Thread[arrayList.Count];
                for (int j = 0; j < arrayList.Count; j++)
                {
                    array[j] = new Thread(new ThreadStart(((threadStart)arrayList[j]).method_0));
                    array[j].Start();
                }
                for (int j = 0; j < array.Length; j++)
                {
                    array[j].Join();
                }
                GC.Collect();
                arrayList.Clear();
            }
            catch (Exception ex)
            {
                Debug.Print(ex.Message);
            }
        }

        #region byte[] 与 hex 的互转
        /// <summary>
        /// byte[]数组转16进制文件
        /// </summary>
        /// <param name="byteContents"></param>
        /// <returns></returns>
        private static String Byte2Hex(byte[] bytContents)
        {
            int length = bytContents.Length;
            StringBuilder builder = new StringBuilder(length * 3);
            foreach (byte value in bytContents)
            {
                builder.AppendFormat("{0:x} ", value);

            }
            return builder.ToString();
        }

        /// <summary>
        /// 16 进制转 byte[] 数组
        /// </summary>
        /// <param name="hexContent">16 进制字符串</param>
        /// <returns></returns>
        public static byte[] Hex2Byte(string hexContent)
        {
            string[] arry = hexContent.Split(' ');
            arry = arry.Skip(0).Take(arry.Length - 1).ToArray();
            List<byte> lstRet = new List<byte>();
            foreach (string s in arry)
            {
                lstRet.Add(Convert.ToByte(s, 16));
            }
            return lstRet.ToArray();
        }
        #endregion


        public static void OXID(string ip)
        {

            string host = ip;
            try
            {
                byte[] response_v0 = new byte[1024];
                using (var sock = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp))
                {
                    sock.Connect(host, 135);
                    sock.Send(buffer_v1);
                    sock.Receive(response_v0);
                    sock.Send(buffer_v2);
                    sock.Receive(response_v0);
                }

                String response_v1 = Byte2Hex(response_v0.Skip(40).ToArray());
                String response_v2 = response_v1.Substring(0, int.Parse(response_v1.IndexOf("9 0 ff ff 0").ToString()));
                String[] hostname_list = response_v2.Split(new string[] { "0 0 0 " }, StringSplitOptions.RemoveEmptyEntries);
                //Console.WriteLine("\n[*] Retrieving network interfaces of {0}", host);
                string outprintf = "\n[*] Retrieving network interfaces of  " + host ;
                for (int i = 0; i < hostname_list.Length - 1; i++)
                {
                    outprintf = outprintf + "\n  [>] Address:" + Encoding.Default.GetString(Hex2Byte(hostname_list[i].Replace(" 0", "")));
                }
                Console.WriteLine(outprintf);
            }
            catch (Exception ex)
            {
                // Console.WriteLine("[!] Error: {0}", ex.Message);
            }

        }

        private static void sleep(int v)
        {
            throw new NotImplementedException();
        }

        static void Main(string[] args)
        {
            if (args.Contains("-c"))
            {
                ThreadList(args[1]);
            }
            else if (args.Contains("-i"))
            {
                OXID(args[1]);
            }
            else
            {
                Console.WriteLine("usage: SharpOXID_Find.exe -i 192.168.0.1");
                Console.WriteLine("usage: SharpOXID_Find.exe -c 192.168.0.1/24");
            }

            Console.WriteLine("Finish!");
        }

    }
}
