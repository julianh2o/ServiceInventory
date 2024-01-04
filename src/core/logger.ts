import winston from 'winston';

const logger = winston.createLogger({
  levels: winston.config.syslog.levels,
  format: winston.format.combine(
    winston.format.label({ label: 'server' }),
    winston.format.simple(),
    winston.format.errors({ stack: true }), // <-- use errors format
    winston.format.timestamp(),
    winston.format.printf((info) => {
      if (info.stack) {
        return `${info.timestamp} [${info.label}] ${info.level}: ${info.message} ${info.stack}`;
      }
      return `${info.timestamp} [${info.label}] ${info.level}: ${info.message}`;
    })
  ),
  transports: [new winston.transports.Console()],
});

export default logger;
