namespace SharedKernal
{
    public interface IServiceResult
    {
        public static readonly Error ServiceError = new("ValidationError", "One or more validation errors occured.");
        Error[] Errors { get; }
    }
}
