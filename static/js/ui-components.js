/**
 * InstaCoach UI Components
 * Componentes reutilizables Alpine.js inspirados en Radix UI
 * Compatible con el sistema de diseño InstaCoach
 */

// ============================================
// KPI CARD COMPONENT
// ============================================
function kpiCard() {
  return {
    title: '',
    value: '',
    change: '',
    trend: 'up',
    icon: 'trending-up',
    gradient: 'from-blue-500 to-cyan-500',
    sparklineData: [],
    
    init() {
      // Inicialización del componente
    },
    
    get trendColor() {
      return this.trend === 'up' ? 'text-green-500' : 'text-red-500';
    },
    
    get trendIcon() {
      return this.trend === 'up' ? '↑' : '↓';
    },
    
    renderSparkline() {
      if (!this.sparklineData.length) return '';
      
      const max = Math.max(...this.sparklineData);
      const min = Math.min(...this.sparklineData);
      const range = max - min || 1;
      
      const points = this.sparklineData.map((value, index) => {
        const x = (index / (this.sparklineData.length - 1)) * 100;
        const y = 100 - ((value - min) / range) * 100;
        return `${x},${y}`;
      }).join(' ');
      
      return `<svg class="w-full h-12 mt-2" viewBox="0 0 100 100" preserveAspectRatio="none">
        <polyline 
          fill="none" 
          stroke="currentColor" 
          stroke-width="2" 
          points="${points}"
          class="text-white opacity-60"
        />
      </svg>`;
    }
  };
}

// ============================================
// STATS CARD COMPONENT
// ============================================
function statsCard() {
  return {
    label: '',
    value: '',
    icon: '',
    color: 'purple',
    loading: false,
    
    get colorClasses() {
      const colors = {
        purple: 'bg-purple-50 text-purple-600',
        blue: 'bg-blue-50 text-blue-600',
        green: 'bg-green-50 text-green-600',
        amber: 'bg-amber-50 text-amber-600',
        pink: 'bg-pink-50 text-pink-600'
      };
      return colors[this.color] || colors.purple;
    }
  };
}

// ============================================
// ACTIVITY FEED COMPONENT
// ============================================
function activityFeed() {
  return {
    activities: [],
    loading: false,
    maxItems: 10,
    
    init() {
      // Inicialización
    },
    
    get visibleActivities() {
      return this.activities.slice(0, this.maxItems);
    },
    
    getActivityIcon(type) {
      const icons = {
        evaluation: '📊',
        new: '👤',
        calendar: '📅',
        content: '📚',
        session: '💬',
        achievement: '🏆'
      };
      return icons[type] || '📌';
    },
    
    getActivityColor(type) {
      const colors = {
        evaluation: 'bg-blue-50 text-blue-600',
        new: 'bg-green-50 text-green-600',
        calendar: 'bg-purple-50 text-purple-600',
        content: 'bg-amber-50 text-amber-600',
        session: 'bg-pink-50 text-pink-600',
        achievement: 'bg-yellow-50 text-yellow-600'
      };
      return colors[type] || 'bg-gray-50 text-gray-600';
    },
    
    formatTime(time) {
      // Formato relativo: "hace 2h", "hace 1d", etc.
      return time;
    },
    
    getInitials(name) {
      return name
        .split(' ')
        .map(word => word[0])
        .join('')
        .toUpperCase()
        .slice(0, 2);
    }
  };
}

// ============================================
// COACHEE CARD COMPONENT
// ============================================
function coacheeCard() {
  return {
    coachee: {
      id: null,
      name: '',
      email: '',
      avatar_url: '',
      progress: 0,
      evaluations_completed: 0,
      evaluations_total: 0,
      last_activity: '',
      status: 'active'
    },
    
    init() {
      // Inicialización
    },
    
    get initials() {
      return this.coachee.name
        .split(' ')
        .map(word => word[0])
        .join('')
        .toUpperCase()
        .slice(0, 2);
    },
    
    get statusBadge() {
      const statuses = {
        active: { label: 'Activo', class: 'badge-success' },
        inactive: { label: 'Inactivo', class: 'badge-warning' },
        pending: { label: 'Pendiente', class: 'badge-info' }
      };
      return statuses[this.coachee.status] || statuses.active;
    },
    
    get progressColor() {
      if (this.coachee.progress >= 75) return 'bg-green-500';
      if (this.coachee.progress >= 50) return 'bg-blue-500';
      if (this.coachee.progress >= 25) return 'bg-amber-500';
      return 'bg-red-500';
    },
    
    viewDetails() {
      // Lógica para ver detalles del coachee
      console.log('View coachee:', this.coachee.id);
    },
    
    sendMessage() {
      // Lógica para enviar mensaje
      console.log('Message coachee:', this.coachee.id);
    }
  };
}

// ============================================
// CONTENT CARD COMPONENT
// ============================================
function contentCard() {
  return {
    content: {
      id: null,
      title: '',
      description: '',
      type: 'article',
      category: '',
      thumbnail_url: '',
      url: '',
      published: true,
      views: 0,
      likes: 0,
      created_at: ''
    },
    
    init() {
      // Inicialización
    },
    
    get typeIcon() {
      const icons = {
        video: '🎥',
        article: '📄',
        document: '📁',
        link: '🔗',
        podcast: '🎧'
      };
      return icons[this.content.type] || '📄';
    },
    
    get typeBadge() {
      const badges = {
        video: { label: 'Video', class: 'badge-purple' },
        article: { label: 'Artículo', class: 'badge-info' },
        document: { label: 'Documento', class: 'badge-success' },
        link: { label: 'Enlace', class: 'badge-warning' },
        podcast: { label: 'Podcast', class: 'badge-pink' }
      };
      return badges[this.content.type] || badges.article;
    },
    
    get statusBadge() {
      return this.content.published 
        ? { label: 'Publicado', class: 'badge-success' }
        : { label: 'Borrador', class: 'badge-warning' };
    },
    
    viewContent() {
      // Abrir contenido
      if (this.content.url) {
        window.open(this.content.url, '_blank');
      }
    },
    
    editContent() {
      console.log('Edit content:', this.content.id);
    },
    
    deleteContent() {
      console.log('Delete content:', this.content.id);
    }
  };
}

// ============================================
// EVALUATION CARD COMPONENT
// ============================================
function evaluationCard() {
  return {
    evaluation: {
      id: null,
      title: '',
      description: '',
      type: 'DISC',
      assigned: 0,
      completed: 0,
      pending: 0,
      average_score: 0,
      status: 'active'
    },
    
    init() {
      // Inicialización
    },
    
    get completionRate() {
      if (this.evaluation.assigned === 0) return 0;
      return Math.round((this.evaluation.completed / this.evaluation.assigned) * 100);
    },
    
    get completionColor() {
      const rate = this.completionRate;
      if (rate >= 75) return 'bg-green-500';
      if (rate >= 50) return 'bg-blue-500';
      if (rate >= 25) return 'bg-amber-500';
      return 'bg-red-500';
    },
    
    get statusBadge() {
      const statuses = {
        active: { label: 'Activa', class: 'badge-success' },
        draft: { label: 'Borrador', class: 'badge-warning' },
        archived: { label: 'Archivada', class: 'badge-error' }
      };
      return statuses[this.evaluation.status] || statuses.active;
    },
    
    viewResults() {
      console.log('View results:', this.evaluation.id);
    },
    
    assignEvaluation() {
      console.log('Assign evaluation:', this.evaluation.id);
    }
  };
}

// ============================================
// PROGRESS BAR COMPONENT
// ============================================
function progressBar() {
  return {
    value: 0,
    max: 100,
    color: 'purple',
    size: 'md',
    showLabel: false,
    animated: true,
    
    get percentage() {
      return Math.round((this.value / this.max) * 100);
    },
    
    get colorClass() {
      const colors = {
        purple: 'bg-purple-500',
        blue: 'bg-blue-500',
        green: 'bg-green-500',
        amber: 'bg-amber-500',
        red: 'bg-red-500'
      };
      return colors[this.color] || colors.purple;
    },
    
    get sizeClass() {
      const sizes = {
        sm: 'h-1',
        md: 'h-2',
        lg: 'h-3'
      };
      return sizes[this.size] || sizes.md;
    }
  };
}

// ============================================
// AVATAR COMPONENT
// ============================================
function avatar() {
  return {
    src: '',
    alt: '',
    name: '',
    size: 'md',
    status: null, // 'online', 'offline', 'busy'
    gradient: false,
    
    get initials() {
      if (!this.name) return '?';
      return this.name
        .split(' ')
        .map(word => word[0])
        .join('')
        .toUpperCase()
        .slice(0, 2);
    },
    
    get sizeClass() {
      const sizes = {
        xs: 'w-6 h-6 text-xs',
        sm: 'w-8 h-8 text-xs',
        md: 'w-10 h-10 text-sm',
        lg: 'w-12 h-12 text-base',
        xl: 'w-16 h-16 text-lg'
      };
      return sizes[this.size] || sizes.md;
    },
    
    get statusColor() {
      const colors = {
        online: 'bg-green-500',
        offline: 'bg-gray-400',
        busy: 'bg-red-500'
      };
      return colors[this.status];
    },
    
    get backgroundClass() {
      if (this.gradient) {
        return 'gradient-purple text-white';
      }
      return 'bg-gray-200 text-gray-600';
    },
    
    imageError(event) {
      event.target.style.display = 'none';
    }
  };
}

// ============================================
// BADGE COMPONENT
// ============================================
function badge() {
  return {
    label: '',
    variant: 'default',
    dot: false,
    
    get variantClass() {
      const variants = {
        default: 'bg-gray-100 text-gray-700',
        success: 'bg-green-50 text-green-700',
        warning: 'bg-amber-50 text-amber-700',
        error: 'bg-red-50 text-red-700',
        info: 'bg-blue-50 text-blue-700',
        purple: 'bg-purple-50 text-purple-700'
      };
      return variants[this.variant] || variants.default;
    }
  };
}

// ============================================
// DROPDOWN COMPONENT
// ============================================
function dropdown() {
  return {
    open: false,
    
    toggle() {
      this.open = !this.open;
    },
    
    close() {
      this.open = false;
    },
    
    init() {
      // Cerrar al hacer click fuera
      this.$watch('open', value => {
        if (value) {
          setTimeout(() => {
            document.addEventListener('click', this.closeOnClickOutside.bind(this));
          }, 0);
        } else {
          document.removeEventListener('click', this.closeOnClickOutside.bind(this));
        }
      });
    },
    
    closeOnClickOutside(event) {
      if (!this.$el.contains(event.target)) {
        this.open = false;
      }
    }
  };
}

// ============================================
// MODAL COMPONENT
// ============================================
function modal() {
  return {
    open: false,
    
    show() {
      this.open = true;
      document.body.style.overflow = 'hidden';
    },
    
    hide() {
      this.open = false;
      document.body.style.overflow = '';
    },
    
    closeOnEscape(event) {
      if (event.key === 'Escape') {
        this.hide();
      }
    }
  };
}

// ============================================
// TOAST NOTIFICATION
// ============================================
function toast() {
  return {
    notifications: [],
    
    show(message, type = 'info', duration = 3000) {
      const id = Date.now();
      this.notifications.push({
        id,
        message,
        type,
        visible: true
      });
      
      setTimeout(() => {
        this.remove(id);
      }, duration);
    },
    
    remove(id) {
      const index = this.notifications.findIndex(n => n.id === id);
      if (index > -1) {
        this.notifications[index].visible = false;
        setTimeout(() => {
          this.notifications.splice(index, 1);
        }, 300);
      }
    },
    
    success(message) {
      this.show(message, 'success');
    },
    
    error(message) {
      this.show(message, 'error');
    },
    
    warning(message) {
      this.show(message, 'warning');
    },
    
    info(message) {
      this.show(message, 'info');
    }
  };
}

// ============================================
// TABS COMPONENT
// ============================================
function tabs() {
  return {
    activeTab: '',
    
    init() {
      // Set first tab as active if none specified
      if (!this.activeTab) {
        const firstTab = this.$el.querySelector('[x-data*="tab"]');
        if (firstTab) {
          this.activeTab = firstTab.getAttribute('data-tab');
        }
      }
    },
    
    isActive(tab) {
      return this.activeTab === tab;
    },
    
    setActive(tab) {
      this.activeTab = tab;
    }
  };
}

// ============================================
// SEARCH/FILTER COMPONENT
// ============================================
function searchFilter() {
  return {
    query: '',
    filters: {},
    items: [],
    
    get filteredItems() {
      let result = this.items;
      
      // Apply search query
      if (this.query) {
        const q = this.query.toLowerCase();
        result = result.filter(item => {
          return JSON.stringify(item).toLowerCase().includes(q);
        });
      }
      
      // Apply filters
      Object.keys(this.filters).forEach(key => {
        if (this.filters[key]) {
          result = result.filter(item => item[key] === this.filters[key]);
        }
      });
      
      return result;
    },
    
    clearFilters() {
      this.query = '';
      this.filters = {};
    },
    
    setFilter(key, value) {
      this.filters[key] = value;
    }
  };
}

// ============================================
// EXPORT COMPONENTS
// ============================================
window.InstaCoachComponents = {
  kpiCard,
  statsCard,
  activityFeed,
  coacheeCard,
  contentCard,
  evaluationCard,
  progressBar,
  avatar,
  badge,
  dropdown,
  modal,
  toast,
  tabs,
  searchFilter
};
