namespace SharpOXID_Find
{
    public class threadStart
    {
        private string ipss = "";

        public threadStart(string ip)
        {
            this.ipss = ip;
        }

        public void method_0()
        {
            Program.OXID(this.ipss);
        }
    }
}