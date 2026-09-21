using Inspector.Common;
using Inspector.Service;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.DependencyInjection;

var config = InspectorConfig.Load();

// Registers this as an actual Windows Service (controllable via Start-Service / Stop-Service / sc.exe).
var builder = Host.CreateApplicationBuilder(args);

builder.Services.AddWindowsService(options =>
{
    options.ServiceName = "InspectorService";
});

// Register config for DI
builder.Services.AddSingleton(config);

// Register worker with config
builder.Services.AddHostedService<Worker>();

var host = builder.Build();
host.Run();