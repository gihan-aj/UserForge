namespace SharedKernal
{
    public interface IServiceResult
    {
        public static readonly Error ServiceError = new("ServiceError", "A service problem occured");
        Error[] Errors { get; }
    }
}
