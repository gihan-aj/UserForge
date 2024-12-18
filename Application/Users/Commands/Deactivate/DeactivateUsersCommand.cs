using Application.Abstractions.Messaging;
using System.Collections.Generic;

namespace Application.Users.Commands.Deactivate
{
    public record DeactivateUsersCommand(List<string> Ids) : ICommand;
}
