#!/usr/bin/env python
# coding: utf-8

# In[1]:


import xml.etree.ElementTree as ET


#Файл rhel-8.oval.xml должен находится в папке с исполняемым кодом или пропишите свой путь
tree = ET.parse('rhel-8.oval.xml')
root = tree.getroot()

#Удаление неймспейсов
for k in root.iter():
    if '}' in k.tag:
        k.tag = k.tag.split('}', 1)[1]
        
#Обработка первых трех <definition> из <definitions> (первые три бюллетени)
definitions_elem = root.find('definitions')
if definitions_elem is not None:
    definition_all = definitions_elem.findall('definition')
    #Можно убрать, чтобы пройтись по всему файлу (по условию задачи оставил первые 3)
    for i in definition_all[3:]:
        definitions_elem.remove(i)
        
#Словари для заполнение нового тега <vulnerable_packages>
tests_map = {}
objects_map = {}
states_map = {}

#Заполнение tests_map для всех rpminfo_test  
'''Есть еще вид"ind-def:textfilecontent54_test", но к нему не стал дописывать проверку, 
т.к. для первых трех он не используется. А так можно сделать еще один тег, который будет 
хранить путь к файлу и по регулярному выражению из state искать совпадение в файле.
Соответственно для object и state подобный формат тоже не обрабатывается.'''

tests = root.find('tests')
if tests is not None:
    for t in tests.findall('rpminfo_test'):
        object_ref = None
        state_ref = None
        object_elem = t.find('object')
        state_elem = t.find('state')
        if object_elem is not None:
            object_ref = object_elem.get('object_ref')
        if state_elem is not None:
            state_ref = state_elem.get('state_ref')
        test_id = t.get('id')
        if test_id:
            tests_map[test_id] = (object_ref, state_ref)
            
#Заполнение objects_map для всех rpminfo_object
objects = root.find('objects')
if objects is not None:
    for ob in objects.findall('rpminfo_object'):
        object_id = ob.get('id')
        name_elem = ob.find('name')
        if object_id and name_elem is not None:
            objects_map[object_id] = name_elem.text
            
#Заполнение states_map для всех rpminfo_state (берем только operator и версию из evr)
states_section = root.find('states')
if states_section is not None:
    for s in states_section.findall('rpminfo_state'):
        state_id = s.get('id')
        evr_elem = s.find('evr')
        if state_id and evr_elem is not None:
            # Логический оператор и значение версии (EVR)
            states_map[state_id] = (evr_elem.get('operation'), evr_elem.text)
            
#Обработка первых трех бюллетеней
for def_elem in definitions_elem.findall('definition'):
    
    #Новый элемент <vulnerable_packages>
    vuln_packages_elem = ET.Element('vulnerable_packages')

    #Цикл по сбору всех критериев
    for crit in def_elem.findall('.//criterion'):
        test_ref = crit.get('test_ref')
        if not test_ref:
            continue
        #Не рассматриваю критерии, если тест отсутствует в rpminfo_test
        if test_ref not in tests_map:
            continue
        object_ref, state_ref = tests_map[test_ref]
        #Получение названия пакета по object_ref
        package_name = objects_map.get(object_ref, "")
        
        #Получение лог. оператора и версии
        operator = None
        version = None
        if state_ref and state_ref in states_map:
            operator, version = states_map[state_ref]
        else:
            continue

        #Новый тег, который будет хранить - пакет, его версию и лог. оператор
        vp_elem = ET.Element('vulnerable_package')
        vp_elem.set('product', package_name)
        if operator:
            vp_elem.set('operator', operator)
        if version:
            vp_elem.set('version', version)
        vuln_packages_elem.append(vp_elem)
        
    #Удаление критериев
    crit_elem = def_elem.find('criteria')
    if crit_elem is not None:
        def_elem.remove(crit_elem)
        
    #Добавление нового тега
    def_elem.append(vuln_packages_elem)
    
#Удаление лишних главных объектов
root.remove(root.find('tests'))
root.remove(root.find('objects'))
root.remove(root.find('states'))


#Сохранение результатов:
# Сохранение в новый файл
tree.write('itog_file_with_3_bull.oval.xml', encoding='utf-8', xml_declaration=True)

#Вывод результатов:
ET.indent(root, space="    ")
print("Мой более упрощенный вариант, где вся информация по бюллетеням находится в одном месте:\n\n\n")
print(ET.tostring(root, encoding="unicode"))


# In[ ]:




