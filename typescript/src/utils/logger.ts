export enum LogLevel {
  DEBUG = 0,
  INFO = 1,
  WARN = 2,
  ERROR = 3,
  NONE = 4
}

export interface LogEntry {
  level: LogLevel;
  message: string;
  timestamp: Date;
  context?: Record<string, any>;
  error?: Error;
}

export interface Logger {
  debug(message: string, context?: Record<string, any>): void;
  info(message: string, context?: Record<string, any>): void;
  warn(message: string, context?: Record<string, any>): void;
  error(message: string, error?: Error | Record<string, any>, context?: Record<string, any>): void;
  setLevel(level: LogLevel): void;
}

export class ConsoleLogger implements Logger {
  private level: LogLevel = LogLevel.INFO;
  
  constructor(level: LogLevel = LogLevel.INFO) {
    this.level = level;
  }
  
  setLevel(level: LogLevel): void {
    this.level = level;
  }
  
  debug(message: string, context?: Record<string, any>): void {
    if (this.level <= LogLevel.DEBUG) {
      console.debug(`[DEBUG] ${new Date().toISOString()} - ${message}`, context || '');
    }
  }
  
  info(message: string, context?: Record<string, any>): void {
    if (this.level <= LogLevel.INFO) {
      console.info(`[INFO] ${new Date().toISOString()} - ${message}`, context || '');
    }
  }
  
  warn(message: string, context?: Record<string, any>): void {
    if (this.level <= LogLevel.WARN) {
      console.warn(`[WARN] ${new Date().toISOString()} - ${message}`, context || '');
    }
  }
  
  error(message: string, error?: Error | Record<string, any>, context?: Record<string, any>): void {
    if (this.level <= LogLevel.ERROR) {
      if (error instanceof Error) {
        console.error(`[ERROR] ${new Date().toISOString()} - ${message}`, error, context || '');
      } else {
        console.error(`[ERROR] ${new Date().toISOString()} - ${message}`, error || '', context || '');
      }
    }
  }
}

export class NoOpLogger implements Logger {
  debug(message: string, context?: Record<string, any>): void {}
  info(message: string, context?: Record<string, any>): void {}
  warn(message: string, context?: Record<string, any>): void {}
  error(message: string, error?: Error | Record<string, any>, context?: Record<string, any>): void {}
  setLevel(level: LogLevel): void {}
}

// Default logger instance
let defaultLogger: Logger = new ConsoleLogger();

export function setDefaultLogger(logger: Logger): void {
  defaultLogger = logger;
}

export function getDefaultLogger(): Logger {
  return defaultLogger;
}