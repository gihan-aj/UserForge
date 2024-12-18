using Application.Abstractions.Messaging;
using System.Collections.Generic;

namespace Application.Users.Commands.Activate
{
    public record ActivateUsersCommand(List<string> Ids) : ICommand;
}
