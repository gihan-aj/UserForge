using Application.Abstractions.Messaging;
using Application.Services;
using SharedKernal;
using System.Threading;
using System.Threading.Tasks;

namespace Application.Users.Commands.Activate
{
    internal sealed class ActivateUsersCommandHandler : ICommandHandler<ActivateUsersCommand>
    {
        private readonly IUsersService _usersService;

        public ActivateUsersCommandHandler(IUsersService usersService)
        {
            _usersService = usersService;
        }

        public Task<Result> Handle(ActivateUsersCommand request, CancellationToken cancellationToken)
        {
            return _usersService.ActivateUsers(request.Ids, cancellationToken);
        }
    }
}
