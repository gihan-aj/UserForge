using Application.Abstractions.Messaging;
using Application.Services;
using SharedKernal;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Application.Users.Commands.Deactivate
{
    internal class DeactivateUsersCommandHandler : ICommandHandler<DeactivateUsersCommand>
    {
        private readonly IUsersService _usersService;

        public DeactivateUsersCommandHandler(IUsersService usersService)
        {
            _usersService = usersService;
        }

        public Task<Result> Handle(DeactivateUsersCommand request, CancellationToken cancellationToken)
        {
            return _usersService.DeactivateUsers(request.Ids, cancellationToken);
        }
    }
}
