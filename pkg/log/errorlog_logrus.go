package log

import (
	"github.com/sirupsen/logrus"
	"mosn.io/pkg/log"
)

func CreateLogrusDelegatedErrorLogger(output string, level log.Level) (log.ErrorLogger, error) {
	return &logrusDelegator{level: level}, nil
}

type logrusDelegator struct {
	level   log.Level
	disable bool
}

func (l *logrusDelegator) Alertf(alert string, format string, args ...interface{}) {
	if l.disable {
		return
	}
	if l.level >= log.ERROR {
		logrus.Printf("[proxy-dataplane] ["+alert+"] "+format, args...)
	}
}

func (l *logrusDelegator) Infof(format string, args ...interface{}) {
	if l.disable {
		return
	}
	logrus.Infof("[proxy-dataplane] "+format, args...)
}

func (l *logrusDelegator) Debugf(format string, args ...interface{}) {
	if l.disable {
		return
	}
	logrus.Debugf("[proxy-dataplane] "+format, args...)
}

func (l *logrusDelegator) Warnf(format string, args ...interface{}) {
	if l.disable {
		return
	}
	logrus.Warnf("[proxy-dataplane] "+format, args...)
}

func (l *logrusDelegator) Errorf(format string, args ...interface{}) {
	if l.disable {
		return
	}
	logrus.Errorf("[proxy-dataplane] "+format, args...)
}

func (l *logrusDelegator) Tracef(format string, args ...interface{}) {
	if l.disable {
		return
	}
	logrus.Tracef("[proxy-dataplane] "+format, args...)
}

func (l *logrusDelegator) Fatalf(format string, args ...interface{}) {
	if l.disable {
		return
	}
	logrus.Fatalf("[proxy-dataplane] "+format, args...)
}

func (l *logrusDelegator) SetLogLevel(level log.Level) {
	l.level = level
}

func (l *logrusDelegator) GetLogLevel() log.Level {
	return l.level
}

func (l *logrusDelegator) Toggle(disable bool) {
	l.disable = disable
}

func (l *logrusDelegator) Disable() bool {
	return l.disable
}
