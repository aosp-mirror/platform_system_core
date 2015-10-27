{
  'target_defaults': {
    'variables': {
      'deps': [
        'libbrillo-<(libbase_ver)',
        'libchrome-<(libbase_ver)',
      ]
    },
    'cflags_cc': [
      '-fno-exceptions',
    ],
  },
  'targets': [
    {
      'target_name': 'libmetrics-<(libbase_ver)',
      'type': 'shared_library',
      'cflags': [
        '-fvisibility=default',
      ],
      'libraries+': [
        '-lpolicy-<(libbase_ver)',
      ],
      'sources': [
        'c_metrics_library.cc',
        'metrics_library.cc',
        'serialization/metric_sample.cc',
        'serialization/serialization_utils.cc',
        'timer.cc',
      ],
      'include_dirs': ['.'],
    },
  ],
}
