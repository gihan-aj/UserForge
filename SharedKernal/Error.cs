namespace SharedKernal
{
    public class Error : IEquatable<Error>
    {
        public static readonly Error None = new(string.Empty, string.Empty);
        public static readonly Error NullValue = new("Error.NullValue", "Null value was provided");

        public Error(string code, string description)
        {
            Code = code;
            Description = description;
        }
        public string Code { get; }
        public string Description { get; }

        public static implicit operator Result(Error error) => Result.Failure(error);

        public static implicit operator string(Error error) => error.Code;

        public static bool operator ==(Error? a, Error? b)
        {
            if (a is null && b is null)
            {
                return true;
            }

            if (a is null || b is null)
            {
                return false;
            }

            return a.Equals(b);
        }

        public static bool operator !=(Error? a, Error? b) => !(a == b);

        public bool Equals(Error? other)
        {
            if (other is null)
            {
                return false;
            }

            return Code == other.Code && Description == other.Description;
        }

        public override bool Equals(object? obj)
        {
            return obj is Error error && Equals(error);
        }

        public override int GetHashCode()
        {
            return HashCode.Combine(Code, Description);
        }

        public override string ToString()
        {
            return Code;
        }

        public Result ToResult() => Result.Failure(this);


    }
}
